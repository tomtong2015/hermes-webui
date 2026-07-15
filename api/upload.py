"""
Hermes Web UI -- File upload: multipart parser and upload handler.
"""
import mimetypes
import os
import re as _re
import tempfile
from pathlib import Path

from api.config import MAX_UPLOAD_BYTES, STATE_DIR
from api.helpers import j
from api.models import get_session
from api.profiles import _profiles_match, get_active_profile_name as _get_active_profile_name
from api.workspace import (
    safe_resolve_ws,
    resolve_trusted_workspace,
    open_anchored_create_fd,
    make_anchored_dir,
    rmtree_anchored,
    unlink_anchored,
)


def _max_extracted_bytes() -> int:
    """Total-extracted-bytes cap for archive uploads (zip/tar-bomb guard).

    Independently tunable from the upload size cap via
    HERMES_WEBUI_MAX_EXTRACTED_MB; defaults to 10x the upload cap. Read at call
    time (not import) so the value reflects the running process's environment
    and is exercisable by tests against the out-of-process test server.
    """
    raw = os.getenv("HERMES_WEBUI_MAX_EXTRACTED_MB", "").strip()
    if raw:
        try:
            mb = float(raw)
            if mb > 0:
                return int(mb * 1024 * 1024)
        except ValueError:
            pass
    return 10 * MAX_UPLOAD_BYTES


def _max_archive_members() -> int:
    """Archive member-count cap (inode-exhaustion guard).

    Independently tunable via HERMES_WEBUI_MAX_ARCHIVE_MEMBERS; defaults to
    200000. Legitimate workspace-backup archives routinely carry tens of
    thousands of small files (agent sessions, skills, caches), so the guard
    must sit well above real use while still bounding a malicious
    million-member archive. Read at call time (not import) so the value
    reflects the running process's environment and is exercisable by tests
    against the out-of-process test server.
    """
    raw = os.getenv("HERMES_WEBUI_MAX_ARCHIVE_MEMBERS", "").strip()
    if raw:
        try:
            n = int(float(raw))
            if n > 0:
                return n
        except ValueError:
            pass
    return 200000


def _extract_sync_wait_s() -> float:
    """How long the workspace-upload handler waits inline for extraction.

    Real archives (many thousand members onto NFS) extract for minutes, but
    the proxy/edge chain in front of the webui gives up on a silent response
    after ~30s — a synchronous handler can never deliver the outcome. So
    extraction runs in a worker thread: the handler waits up to this many
    seconds (small archives keep the immediate success/error response) and
    otherwise answers `extracted: "pending"` + a job id the client polls via
    /api/workspace/upload-status. Env: HERMES_WEBUI_EXTRACT_SYNC_WAIT_S.
    """
    raw = os.getenv("HERMES_WEBUI_EXTRACT_SYNC_WAIT_S", "").strip()
    if raw:
        try:
            v = float(raw)
            if v >= 0:
                return min(v, 25.0)
        except ValueError:
            pass
    return 15.0


# In-memory registry of background extraction jobs (single-process server).
# Bounded: finished jobs are pruned oldest-first past _EXTRACT_JOBS_MAX.
_EXTRACT_JOBS: dict = {}
_EXTRACT_JOBS_MAX = 50


def _extract_jobs_put(job: dict) -> None:
    _EXTRACT_JOBS[job['id']] = job
    if len(_EXTRACT_JOBS) > _EXTRACT_JOBS_MAX:
        finished = [j_ for j_ in _EXTRACT_JOBS.values() if j_['state'] != 'running']
        finished.sort(key=lambda j_: j_.get('finished', 0))
        for j_ in finished[:len(_EXTRACT_JOBS) - _EXTRACT_JOBS_MAX]:
            _EXTRACT_JOBS.pop(j_['id'], None)


def handle_workspace_upload_status(handler, parsed):
    """Report the state of a background archive-extraction job."""
    from urllib.parse import parse_qs
    job_id = (parse_qs(parsed.query).get('job') or [''])[0]
    job = _EXTRACT_JOBS.get(job_id)
    if not job:
        return j(handler, {'error': 'Unknown extraction job'}, status=404)
    return j(handler, {k: v for k, v in job.items() if k != '_thread'})


# Back-compat module constant (some call sites / tests reference it). The
# authoritative value is _max_extracted_bytes(), read at extraction time.
_MAX_EXTRACTED_BYTES = 10 * MAX_UPLOAD_BYTES


def parse_multipart(rfile, content_type, content_length) -> tuple:
    import re as _re, email.parser as _ep
    # Imported locally (not just module-level) so the function stays
    # self-contained — some tests exec() this function's source in an isolated
    # namespace, and a bare module global would NameError there.
    try:
        from api.config import MAX_UPLOAD_BYTES as _MAX_UPLOAD_BYTES
    except Exception:
        _MAX_UPLOAD_BYTES = 20 * 1024 * 1024
    m = _re.search(r'boundary=([^;\s]+)', content_type)
    if not m:
        raise ValueError('No boundary in Content-Type')
    boundary = m.group(1).strip('"').encode()
    # Centralized length guard for ALL upload callers: a missing/garbage or
    # NEGATIVE Content-Length must never reach rfile.read(<0), which reads the
    # stream unbounded (read(-1) == read-to-EOF) and bypasses the per-handler
    # size cap. Reject anything not in [0, MAX_UPLOAD_BYTES].
    try:
        length = int(content_length)
    except (TypeError, ValueError):
        raise ValueError('Invalid Content-Length') from None
    if length < 0:
        raise ValueError('Invalid Content-Length (negative)')
    if length > _MAX_UPLOAD_BYTES:
        raise ValueError(f'Upload too large (max {_MAX_UPLOAD_BYTES} bytes)')
    raw = rfile.read(length)
    fields = {}
    files = {}
    delimiter = b'--' + boundary
    parts = raw.split(delimiter)
    for part in parts[1:]:
        stripped = part.lstrip(b'\r\n')
        if stripped.startswith(b'--'):
            break
        sep = b'\r\n\r\n' if b'\r\n\r\n' in part else b'\n\n'
        if sep not in part:
            continue
        header_raw, body = part.split(sep, 1)
        if body.endswith(b'\r\n'):
            body = body[:-2]
        elif body.endswith(b'\n'):
            body = body[:-1]
        header_text = header_raw.lstrip(b'\r\n').decode('utf-8', errors='replace')
        msg = _ep.HeaderParser().parsestr(header_text)
        disp = msg.get('Content-Disposition', '')
        name_m = _re.search(r'name="([^"]*)"', disp)
        file_m = _re.search(r'filename="([^"]*)"', disp)
        if not name_m:
            continue
        name = name_m.group(1)
        if file_m:
            files[name] = (file_m.group(1), body)
        else:
            fields[name] = body.decode('utf-8', errors='replace')
    return fields, files


def _sanitize_upload_name(filename: str) -> str:
    safe_name = _re.sub(r'[^\w.\-]', '_', Path(filename).name)[:200]
    if not safe_name or safe_name.strip('.') == '':
        raise ValueError('Invalid filename')
    return safe_name


def _attachment_root() -> Path:
    """Return the configured upload inbox root.

    Plain chat attachments are transient context for the agent, not project
    source files.  Keep them out of the active workspace by default while still
    allowing operators to move the inbox with HERMES_WEBUI_ATTACHMENT_DIR.
    """
    override = os.getenv('HERMES_WEBUI_ATTACHMENT_DIR', '').strip()
    if override:
        return Path(override).expanduser().resolve()
    return (STATE_DIR / 'attachments').resolve()


def _upload_destination(session_id: str, safe_name: str) -> Path:
    dest_dir = _session_attachment_dir(session_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = (dest_dir / safe_name).resolve()
    if not dest.is_relative_to(dest_dir):
        raise ValueError('Invalid upload destination')
    if dest.exists():
        stem = dest.stem
        suffix = dest.suffix
        for idx in range(1, 1000):
            candidate = (dest_dir / f'{stem}-{idx}{suffix}').resolve()
            if not candidate.is_relative_to(dest_dir):
                raise ValueError('Invalid upload destination')
            if not candidate.exists():
                return candidate
        raise ValueError('Too many uploads with the same filename')
    return dest


def _session_attachment_dir(session_id: str, *, root: Path | None = None) -> Path:
    root = (root or _attachment_root()).resolve()
    dest_dir = (root / _re.sub(r'[^\w.\-]', '_', str(session_id or 'session'))[:120]).resolve()
    if not dest_dir.is_relative_to(root):
        raise ValueError('Invalid attachment directory')
    return dest_dir


def _session_visible_to_active_profile(session) -> bool:
    """Return whether an upload target session belongs to the active profile."""
    session_profile = getattr(session, 'profile', None)
    if not isinstance(session_profile, str):
        session_profile = None
    return _profiles_match(session_profile, _get_active_profile_name())


def _reject_invisible_session(handler, session) -> bool:
    if _session_visible_to_active_profile(session):
        return False
    j(handler, {'error': 'Session not found'}, status=404)
    return True


def _write_office_upload_sidecar(workspace: Path, dest: Path, file_bytes: bytes) -> dict | None:
    """Write a Markdown preview sidecar for supported Office uploads."""
    if dest.suffix.lower() not in {'.docx', '.xlsx', '.pptx'}:
        return None

    error_message = 'Office sidecar extraction failed'
    sidecar = dest.with_name(f'{dest.name}.md')
    sidecar_path = sidecar.resolve()
    created_sidecar = False
    try:
        from api.office_documents import preview_office_document

        preview = preview_office_document(dest.name, file_bytes)
        if not sidecar_path.is_relative_to(workspace.resolve()):
            raise ValueError('Invalid sidecar destination')
        sidecar_fd = open_anchored_create_fd(workspace, sidecar_path)
        created_sidecar = True
        with os.fdopen(sidecar_fd, 'w', encoding='utf-8', closefd=True) as sidecar_file:
            sidecar_file.write(str(preview.get('content') or ''))
        return {
            'filename': sidecar_path.name,
            'path': str(sidecar_path),
            'size': sidecar_path.stat().st_size,
            'preview_kind': preview.get('preview_kind'),
            'office_format': preview.get('office_format'),
        }
    except FileExistsError:
        return {'error': error_message}
    except Exception:
        if created_sidecar:
            try:
                unlink_anchored(workspace, sidecar_path)
            except FileNotFoundError:
                pass
            except Exception:
                pass
        return {'error': error_message}


def handle_upload(handler):
    import traceback as _tb
    try:
        content_type = handler.headers.get('Content-Type', '')
        content_length = int(handler.headers.get('Content-Length', 0) or 0)
        if content_length > MAX_UPLOAD_BYTES:
            return j(handler, {'error': f'File too large (max {MAX_UPLOAD_BYTES//1024//1024}MB)'}, status=413)
        fields, files = parse_multipart(handler.rfile, content_type, content_length)
        session_id = fields.get('session_id', '')
        if 'file' not in files:
            return j(handler, {'error': 'No file field in request'}, status=400)
        filename, file_bytes = files['file']
        if not filename:
            return j(handler, {'error': 'No filename in upload'}, status=400)
        try:
            s = get_session(session_id)
        except KeyError:
            return j(handler, {'error': 'Session not found'}, status=404)
        if _reject_invisible_session(handler, s):
            return True
        safe_name = _sanitize_upload_name(filename)
        dest = _upload_destination(session_id, safe_name)
        dest.write_bytes(file_bytes)
        mime = mimetypes.guess_type(safe_name)[0] or 'application/octet-stream'
        return j(handler, {
            'filename': dest.name,
            'path': str(dest),
            'size': dest.stat().st_size,
            'mime': mime,
            'is_image': mime.startswith('image/'),
        })
    except ValueError as e:
        return j(handler, {'error': str(e)}, status=400)
    except Exception:
        print('[webui] upload error: ' + _tb.format_exc(), flush=True)
        return j(handler, {'error': 'Upload failed'}, status=500)


def extract_archive(file_bytes: bytes, filename: str, workspace: Path):
    """Extract a zip or tar archive into the workspace.

    Returns a dict with ``extracted`` (int), ``files`` (list[str]).
    Raises ValueError on zip-slip or unsupported format.
    """
    import zipfile, tarfile, io, os

    cap = _max_extracted_bytes()
    name = Path(filename).name
    stem = Path(filename).stem  # strip .zip / .tar.gz etc.

    if name.lower().endswith(('.zip',)):
        _mode = 'zip'
    elif name.lower().endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz')):
        _mode = 'tar'
    else:
        raise ValueError(f'Unsupported archive format: {filename}')

    # Parse the archive and enforce the member-count cap BEFORE creating the
    # staging directory or writing anything: a cap violation (or a corrupt
    # archive) must reject the whole upload without leaving a partial —
    # and therefore misleading — staging dir behind. The old mid-flight
    # count check extracted the first N members and then aborted, which
    # real workspace-backup archives tripped in production.
    if _mode == 'zip':
        archive = zipfile.ZipFile(io.BytesIO(file_bytes))
    else:
        archive = tarfile.open(fileobj=io.BytesIO(file_bytes))
    try:
        if _mode == 'zip':
            file_members = [m for m in archive.infolist() if not m.is_dir()]
        else:
            file_members = [m for m in archive.getmembers() if m.isfile()]
        max_members = _max_archive_members()
        if len(file_members) > max_members:
            raise ValueError(
                f'Archive has too many files ({len(file_members)} > {max_members}). '
                f'Possible archive bomb. If this is a legitimate archive, raise '
                f'HERMES_WEBUI_MAX_ARCHIVE_MEMBERS.'
            )

        # Determine destination directory — use archive stem as folder name
        dest_dir = safe_resolve_ws(workspace, stem)
        # Avoid overwriting existing files by appending a suffix (bounded — astronomically
        # unlikely to collide, but never spin forever).
        if dest_dir.exists():
            import string, random
            for _ in range(1000):
                if not dest_dir.exists():
                    break
                suffix = ''.join(random.choices(string.digits, k=3))
                dest_dir = safe_resolve_ws(workspace, stem).with_name(stem + '_' + suffix)
            else:
                raise ValueError('Could not allocate a unique extraction directory')
        # #3398: create the extraction root race-safely under the true workspace root.
        make_anchored_dir(workspace, dest_dir)

        extracted_files = []
        total_extracted = 0

        try:
            if _mode == 'zip':
                for member in file_members:
                    # Zip-slip protection
                    member_path = (dest_dir / member.filename).resolve()
                    if not member_path.is_relative_to(dest_dir.resolve()):
                        raise ValueError(f'Zip-slip blocked: {member.filename}')
                    # Zip-bomb protection: track actual extracted bytes (not declared file_size)
                    if total_extracted > cap:
                        raise ValueError(
                            f'Extraction too large ({total_extracted // (1024*1024)} MB > '
                            f'{cap // (1024*1024)} MB limit). '
                            f'Possible zip bomb.'
                        )
                    # #3398: open_anchored_create_fd creates intermediate dirs
                    # race-safely under the true workspace root (anchored mkdirat),
                    # so no pathname member_path.parent.mkdir() before it (which
                    # could be redirected outside by a raced symlink component).
                    _mfd = open_anchored_create_fd(workspace, member_path)
                    with archive.open(member) as src, os.fdopen(_mfd, 'wb', closefd=True) as dst:
                        _chunk_size = 65536
                        while True:
                            chunk = src.read(_chunk_size)
                            if not chunk:
                                break
                            total_extracted += len(chunk)
                            if total_extracted > cap:
                                raise ValueError(
                                    f'Extraction too large (> '
                                    f'{cap // (1024*1024)} MB limit). '
                                    f'Possible zip bomb.'
                                )
                            dst.write(chunk)
                    extracted_files.append(str(member_path.relative_to(workspace.resolve())))

            elif _mode == 'tar':
                for member in file_members:
                    # Tar-slip protection
                    member_path = (dest_dir / member.name).resolve()
                    if not member_path.is_relative_to(dest_dir.resolve()):
                        raise ValueError(f'Tar-slip blocked: {member.name}')
                    # Tar-bomb protection: track actual extracted bytes (not declared size)
                    if total_extracted > cap:
                        raise ValueError(
                            f'Extraction too large ({total_extracted // (1024*1024)} MB > '
                            f'{cap // (1024*1024)} MB limit). '
                            f'Possible zip bomb.'
                        )
                    # #3398: anchored member create makes intermediate dirs
                    # race-safely; no pathname member_path.parent.mkdir() first.
                    src_obj = archive.extractfile(member)
                    if src_obj:
                        # #3398: fd-anchored member create under the TRUE workspace root.
                        _mfd = open_anchored_create_fd(workspace, member_path)
                        with src_obj as src, os.fdopen(_mfd, 'wb', closefd=True) as dst:
                            _chunk_size = 65536
                            while True:
                                chunk = src.read(_chunk_size)
                                if not chunk:
                                    break
                                total_extracted += len(chunk)
                                if total_extracted > cap:
                                    raise ValueError(
                                        f'Extraction too large (> '
                                        f'{cap // (1024*1024)} MB limit). '
                                        f'Possible zip bomb.'
                                    )
                                dst.write(chunk)
                    extracted_files.append(str(member_path.relative_to(workspace.resolve())))
        except Exception:
            # Clean up the partially-extracted directory to avoid orphaned
            # folders. On NFS, an unlinked file that something still holds
            # open leaves a .nfs* silly-rename entry that fails rmtree with
            # ENOTEMPTY — retry once after a beat, and if the dir still
            # survives, say so loudly: a silently-kept partial staging dir
            # reads as a successful extraction to the user.
            import time as _time
            for _attempt in range(2):
                try:
                    rmtree_anchored(workspace, dest_dir)
                except Exception:
                    pass
                if not dest_dir.exists():
                    break
                _time.sleep(0.5)
            if dest_dir.exists():
                print(f'[webui] WARNING: cleanup of partial extraction failed — '
                      f'incomplete staging dir left at {dest_dir}', flush=True)
            raise
    finally:
        archive.close()

    return {'extracted': len(extracted_files), 'files': extracted_files, 'dest': str(dest_dir)}


def handle_upload_extract(handler):
    """Handle archive upload and extraction."""
    import traceback as _tb
    try:
        content_type = handler.headers.get('Content-Type', '')
        content_length = int(handler.headers.get('Content-Length', 0) or 0)
        if content_length > MAX_UPLOAD_BYTES:
            return j(handler, {'error': f'File too large (max {MAX_UPLOAD_BYTES//1024//1024}MB)'}, status=413)
        fields, files = parse_multipart(handler.rfile, content_type, content_length)
        session_id = fields.get('session_id', '')
        if 'file' not in files:
            return j(handler, {'error': 'No file field in request'}, status=400)
        filename, file_bytes = files['file']
        if not filename:
            return j(handler, {'error': 'No filename in upload'}, status=400)
        try:
            s = get_session(session_id)
        except KeyError:
            return j(handler, {'error': 'Session not found'}, status=404)
        if _reject_invisible_session(handler, s):
            return True
        session_dir = _session_attachment_dir(session_id)
        session_dir.mkdir(parents=True, exist_ok=True)
        result = extract_archive(file_bytes, filename, session_dir)
        return j(handler, {'ok': True, **result})
    except ValueError as e:
        return j(handler, {'error': str(e)}, status=400)
    except Exception:
        print('[webui] upload extract error: ' + _tb.format_exc(), flush=True)
        return j(handler, {'error': 'Archive extraction failed'}, status=500)


def handle_transcribe(handler):
    import traceback as _tb
    temp_path = None
    try:
        content_type = handler.headers.get('Content-Type', '')
        content_length = int(handler.headers.get('Content-Length', 0) or 0)
        if content_length > MAX_UPLOAD_BYTES:
            return j(handler, {'error': f'File too large (max {MAX_UPLOAD_BYTES//1024//1024}MB)'}, status=413)
        fields, files = parse_multipart(handler.rfile, content_type, content_length)
        if 'file' not in files:
            return j(handler, {'error': 'No file field in request'}, status=400)
        filename, file_bytes = files['file']
        if not filename:
            return j(handler, {'error': 'No filename in upload'}, status=400)
        safe_name = _sanitize_upload_name(filename)
        suffix = Path(safe_name).suffix or '.webm'
        with tempfile.NamedTemporaryFile(prefix='webui-stt-', suffix=suffix, delete=False) as tmp:
            temp_path = tmp.name
            tmp.write(file_bytes)
        try:
            from tools.transcription_tools import transcribe_audio
        except ImportError:
            return j(handler, {'error': 'Speech-to-text is unavailable on this server'}, status=503)
        result = transcribe_audio(temp_path)
        if not result.get('success'):
            msg = str(result.get('error') or 'Transcription failed')
            status = 503 if 'unavailable' in msg.lower() or 'not configured' in msg.lower() else 400
            return j(handler, {'error': msg}, status=status)
        transcript = str(result.get('transcript') or '').strip()
        return j(handler, {'ok': True, 'transcript': transcript})
    except ValueError as e:
        return j(handler, {'error': str(e)}, status=400)
    except Exception:
        print('[webui] transcribe error: ' + _tb.format_exc(), flush=True)
        return j(handler, {'error': 'Transcription failed'}, status=500)
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass


def _stt_provider_capability_from_module(stt):
    """Return (available, provider) for a loaded transcription_tools module."""
    try:
        load_cfg = getattr(stt, "_load_stt_config", None)
        stt_config = load_cfg() if callable(load_cfg) else {}
        cfg_dict = stt_config if isinstance(stt_config, dict) else {}
        is_enabled = getattr(stt, "is_stt_enabled", None)
        if callable(is_enabled) and not is_enabled(stt_config):
            return False, "none"

        # Some tests and future agent releases expose the provider decision as a
        # single helper. Use it when the lower-level capability flags are not
        # available. The current agent module exposes the flags below, so the
        # normal path mirrors _get_provider() without triggering its lazy local
        # STT install side effect during a passive web page probe.
        has_internal_flags = any(
            hasattr(stt, name)
            for name in ("_HAS_FASTER_WHISPER", "_HAS_OPENAI", "_HAS_MISTRAL")
        )
        get_provider = getattr(stt, "_get_provider", None)
        if callable(get_provider) and not has_internal_flags:
            provider = str(get_provider(stt_config) or "none")
            return provider not in ("", "none"), provider or "none"

        def env(name):
            getter = getattr(stt, "get_env_value", None)
            try:
                if callable(getter):
                    return str(getter(name) or "").strip()
            except Exception:
                return ""
            return os.getenv(name, "").strip()

        def has_local_command():
            helper = getattr(stt, "_has_local_command", None)
            try:
                return bool(helper()) if callable(helper) else False
            except Exception:
                return False

        def has_browser_audio_converter():
            helper = getattr(stt, "_find_ffmpeg_binary", None)
            try:
                return bool(helper()) if callable(helper) else False
            except Exception:
                return False

        def has_openai_audio():
            helper = getattr(stt, "_has_openai_audio_backend", None)
            try:
                return bool(helper()) if callable(helper) else False
            except Exception:
                return False

        def local_command_available():
            # The browser sends WebM/Ogg blobs; the local-command path converts
            # non-WAV input through ffmpeg before invoking the command.
            return has_local_command() and has_browser_audio_converter()

        def command_provider_available(provider):
            resolver = getattr(stt, "_resolve_command_stt_provider_config", None)
            try:
                return callable(resolver) and resolver(provider, cfg_dict) is not None
            except Exception:
                return False

        def resolve_provider(provider):
            if provider == "local":
                if bool(getattr(stt, "_HAS_FASTER_WHISPER", False)):
                    return "local"
                if local_command_available():
                    return "local_command"
                return "none"
            if provider == "local_command":
                if local_command_available():
                    return "local_command"
                if bool(getattr(stt, "_HAS_FASTER_WHISPER", False)):
                    return "local"
                return "none"
            if provider == "groq":
                return "groq" if bool(getattr(stt, "_HAS_OPENAI", False)) and bool(env("GROQ_API_KEY")) else "none"
            if provider == "openai":
                return "openai" if bool(getattr(stt, "_HAS_OPENAI", False)) and has_openai_audio() else "none"
            if provider == "mistral":
                return "mistral" if bool(getattr(stt, "_HAS_MISTRAL", False)) and bool(env("MISTRAL_API_KEY")) else "none"
            if provider == "xai":
                try:
                    from tools.xai_http import resolve_xai_http_credentials

                    return "xai" if resolve_xai_http_credentials().get("api_key") else "none"
                except Exception:
                    return "none"
            if provider == "elevenlabs":
                return "elevenlabs" if bool(env("ELEVENLABS_API_KEY")) else "none"
            if command_provider_available(provider):
                return provider
            return "none"

        explicit = "provider" in cfg_dict
        if explicit:
            configured = str(cfg_dict.get("provider") or "local")
            provider = resolve_provider(configured)
            return provider != "none", provider if provider != "none" else configured

        for candidate in ("local", "local_command", "groq", "openai", "mistral", "xai", "elevenlabs"):
            # Command (custom) STT providers are intentionally omitted from this
            # auto-detect tuple to mirror the agent's _get_provider() (transcription_tools.py),
            # which only auto-selects local > groq > openai and never auto-picks a command
            # provider. A command-backed STT activates only via an explicit stt.provider.
            # Do NOT add command providers here without matching the agent, or the WebUI
            # probe will diverge from what the agent actually resolves.
            provider = resolve_provider(candidate)
            if provider != "none":
                return True, provider
        return False, "none"
    except Exception:
        return False, "none"



def _stt_provider_capability():
    """Return (available, provider) for a cheap server-side STT capability probe."""
    try:
        import tools.transcription_tools as stt
    except ImportError:
        return False, "none"
    return _stt_provider_capability_from_module(stt)


def handle_transcribe_capability(handler):
    available, provider = _stt_provider_capability()
    return j(handler, {"ok": True, "available": bool(available), "provider": provider})


def handle_workspace_upload(handler):
    """Upload a file into a session's workspace directory.

    Form fields:
        session_id – target session
        path       – subdirectory within the workspace (default: '')
    File:
        file – the uploaded file(s)
    """
    import traceback as _tb
    try:
        content_type = handler.headers.get('Content-Type', '')
        content_length = int(handler.headers.get('Content-Length', 0) or 0)
        if content_length > MAX_UPLOAD_BYTES:
            return j(handler, {'error': f'File too large (max {MAX_UPLOAD_BYTES//1024//1024}MB)'}, status=413)

        fields, files = parse_multipart(handler.rfile, content_type, content_length)
        session_id = fields.get('session_id', '')
        subpath = fields.get('path', '')
        # Optional client override of the inline extraction wait (clamped to
        # the same [0, 25]s range as the env default) — lets a client opt into
        # an immediate pending response; also how tests exercise the async path.
        extract_wait = _extract_sync_wait_s()
        _wait_raw = str(fields.get('extract_wait', '')).strip()
        if _wait_raw:
            try:
                extract_wait = max(0.0, min(float(_wait_raw), 25.0))
            except ValueError:
                pass

        if not session_id:
            return j(handler, {'error': 'Missing session_id'}, status=400)

        if not files:
            return j(handler, {'error': 'No file field in request'}, status=400)

        # Validate session
        try:
            session = get_session(session_id)
        except KeyError:
            return j(handler, {'error': 'Session not found'}, status=404)
        if _reject_invisible_session(handler, session):
            return True

        # Resolve workspace root from session
        workspace = resolve_trusted_workspace(session.workspace)

        # Resolve target subdirectory within workspace
        target_dir = safe_resolve_ws(workspace, subpath) if subpath else workspace
        # safe_resolve_ws intentionally permits in-workspace symlinks pointing
        # outside the root (read trust model). For an UPLOAD target that's not
        # acceptable: a planted symlink subpath would let mkdir() + writes create
        # files OUTSIDE the workspace. Require the resolved target to be inside
        # the workspace before creating anything. (is_relative_to is True for the
        # workspace==target equality case, so the normal subpath='' path passes.)
        if not target_dir.resolve().is_relative_to(workspace.resolve()):
            return j(handler, {'error': 'Upload target escapes workspace'}, status=403)
        # #3398: create the upload target dir race-safely under the workspace root
        # (anchored mkdirat) so a raced symlink subpath can't mkdir outside.
        try:
            make_anchored_dir(workspace, target_dir)
        except (ValueError, OSError):
            return j(handler, {'error': 'Upload target escapes workspace'}, status=403)

        results = []
        for _field_name, (filename, file_bytes) in files.items():
            if not filename:
                continue

            safe_name = _sanitize_upload_name(filename)
            dest = safe_resolve_ws(target_dir, safe_name)

            # Path traversal guard (belt-and-suspenders: safe_resolve_ws above is
            # the authoritative guard and raises ValueError on traversal; this
            # check catches any edge case where the resolved path escapes).
            if not dest.resolve().is_relative_to(workspace.resolve()):
                return j(handler, {'error': f'Path traversal blocked: {safe_name}'}, status=403)

            # Deduplicate: append -1, -2, etc. if file already exists
            if dest.exists():
                stem = dest.stem
                suffix = dest.suffix
                for idx in range(1, 1000):
                    candidate = safe_resolve_ws(target_dir, f'{stem}-{idx}{suffix}')
                    if not candidate.resolve().is_relative_to(workspace.resolve()):
                        return j(handler, {'error': 'Path traversal blocked'}, status=403)
                    if not candidate.exists():
                        dest = candidate
                        break
                else:
                    return j(handler, {'error': 'Too many uploads with the same filename'}, status=400)

            # #3398 TOCTOU hardening: create the destination via an anchored
            # openat-walk from the true workspace root with O_CREAT|O_EXCL|
            # O_NOFOLLOW, so a symlink raced into any path component after the
            # containment checks above cannot redirect the write outside the
            # workspace. The dedup loop guarantees `dest` does not exist.
            try:
                _wfd = open_anchored_create_fd(workspace, dest.resolve())
            except FileExistsError:
                return j(handler, {'error': f'Upload destination already exists: {safe_name}'}, status=409)
            except (ValueError, OSError):
                return j(handler, {'error': f'Path traversal blocked: {safe_name}'}, status=403)
            with os.fdopen(_wfd, 'wb', closefd=True) as _wfh:
                _wfh.write(file_bytes)
            mime = mimetypes.guess_type(safe_name)[0] or 'application/octet-stream'

            # For archives, optionally extract into the target directory.
            # Suffix set MUST match extract_archive()'s supported formats, else
            # accepted-but-unlisted archives (.tar/.tbz2/.txz) silently land as
            # raw files instead of extracting.
            is_archive = safe_name.lower().endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz'))
            if is_archive:
                import zipfile, tarfile, traceback as _extract_tb
                import threading, time as _time, uuid as _uuid

                # Extraction runs in a worker thread: a big archive extracts
                # for minutes (thousands of members onto NFS) while the
                # proxy/edge in front of the webui 504s any response that is
                # silent for ~30s. The handler waits _extract_sync_wait_s()
                # inline — small archives keep the immediate outcome — and
                # otherwise reports the job as pending for the client to poll
                # via /api/workspace/upload-status.
                job = {
                    'id': _uuid.uuid4().hex[:12],
                    'state': 'running',
                    'filename': safe_name,
                    'started': _time.time(),
                }
                _extract_jobs_put(job)
                _dest_resolved = dest.resolve()

                def _bg_extract(job=job, file_bytes=file_bytes, safe_name=safe_name,
                                target_dir=target_dir, workspace=workspace,
                                _dest_resolved=_dest_resolved, dest_name=dest.name):
                    try:
                        extraction = extract_archive(file_bytes, safe_name, target_dir)
                        # Remove the archive file after successful extraction
                        try:
                            unlink_anchored(workspace, _dest_resolved)
                        except FileNotFoundError:
                            pass
                        job.update({
                            'state': 'done',
                            'dest': extraction.get('dest', str(target_dir)),
                            'extracted_count': extraction.get('extracted', 0),
                            'extracted_files': extraction.get('files', []),
                            'finished': _time.time(),
                        })
                    except (zipfile.BadZipFile, tarfile.TarError, ValueError) as e:
                        # Extraction failed — KEEP the uploaded archive and
                        # surface the error. Deleting it here destroys the
                        # user's only pod-side copy, which is fatal in a
                        # backup-restore flow; a kept archive can still be
                        # extracted manually (tar/unzip in the terminal) after
                        # the guard that tripped is resolved.
                        print(f'[webui] workspace upload extract error: {e}', flush=True)
                        job.update({
                            'state': 'error',
                            'archive_kept': True,
                            'error': (str(e) or 'Archive extraction failed')
                                     + f' — uploaded archive kept as {dest_name}',
                            'finished': _time.time(),
                        })
                    except Exception:
                        print('[webui] workspace upload extract error: ' + _extract_tb.format_exc(), flush=True)
                        job.update({
                            'state': 'error',
                            'archive_kept': True,
                            'error': f'Archive extraction failed — uploaded archive kept as {dest_name}',
                            'finished': _time.time(),
                        })

                _th = threading.Thread(target=_bg_extract, daemon=True,
                                       name=f'ws-extract-{job["id"]}')
                _th.start()
                _th.join(timeout=extract_wait)

                if job['state'] == 'done':
                    results.append({
                        'filename': safe_name,
                        'path': job['dest'],
                        'size': len(file_bytes),
                        'is_image': False,
                        'extracted': True,
                        'extracted_files': job['extracted_files'],
                        'extracted_count': job['extracted_count'],
                    })
                elif job['state'] == 'error':
                    results.append({
                        'filename': safe_name,
                        'path': str(dest),
                        'size': len(file_bytes),
                        'mime': mime,
                        'is_image': False,
                        'extracted': False,
                        'archive_kept': True,
                        'extract_error': job['error'],
                    })
                else:
                    results.append({
                        'filename': safe_name,
                        'path': str(dest),
                        'size': len(file_bytes),
                        'mime': mime,
                        'is_image': False,
                        'extracted': 'pending',
                        'extract_job': job['id'],
                    })
                continue

            sidecar = _write_office_upload_sidecar(workspace, dest, file_bytes)
            results.append({
                'filename': dest.name,
                'path': str(dest),
                'size': dest.stat().st_size,
                'mime': mime,
                'is_image': mime.startswith('image/'),
                'extracted': False,
                **({'sidecar': sidecar} if sidecar and 'error' not in sidecar else {}),
                **({'sidecar_error': sidecar['error']} if sidecar and 'error' in sidecar else {}),
            })

        if len(results) == 1:
            return j(handler, results[0])
        return j(handler, {'files': results, 'count': len(results)})
    except ValueError as e:
        return j(handler, {'error': str(e)}, status=400)
    except Exception:
        print('[webui] workspace upload error: ' + _tb.format_exc(), flush=True)
        return j(handler, {'error': 'Upload failed'}, status=500)
