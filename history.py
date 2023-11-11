"""
Plugin for profanity to open text editor with full chat history of current user using /hh command.
"""

import os
import prof
import re
import sqlite3

from pathlib import Path

_editor = ""
_current_user = ""
_logs_dir = ""
_db_file = ""
_win = "History"
_plugin_name = __file__.split('/')[-1] if __file__ else "history.py"


def _handle_win_input():
    pass


def _create_win(win):
    if not prof.win_exists(win):
        prof.win_create(win, _handle_win_input)


def _show_error(error):
    error_msg = f"[History Reader] Error happened: {error}"
    prof.cons_alert()
    prof.cons_show(error_msg)
    prof.log_error(error_msg)
    return


def _str_sanitize(text):
    return re.sub('[^a-zA-Z0-9\._]', '', text.replace("@", "_at_"))


def _cmd_editor(*args):
    global _editor
    _db_connection = sqlite3.connect(f"{_db_file}")
    _db_connection.text_factory = bytes
    _cur = _db_connection.cursor()
    msg_buffer = []
    if args and args[0] == "set":
        if len(args) < 2:
            prof.cons_show("Please, use this format: \"/hh set <editor>\"")
            return
        _editor = args[1]
        prof.settings_string_set("history", "editor", _editor)
        prof.cons_show(
            f"New editor set up successfully. New editor: {_editor}")
        return
    if args and args[0] == "--no-repeat":
        prof.cons_show("[History Reader] Trying operation again...")
    if not _current_user:
        if args and args[0] == "--no-repeat":
            _show_error("Can't fetch current user.")
            return
        prof.send_line(f"/plugins reload {_plugin_name}")
        prof.send_line("/hh --no-repeat")
        return
    if not _editor:
        prof.cons_show(
            "Please, set up editor using /hh set. E.g. /hh set /usr/bin/vim")
        return
    if not (recipient := prof.get_current_recipient()):
        prof.cons_show("Please, use this command in a chat window")
        return

    tmpfpath = _logs_dir / f"{_str_sanitize(recipient)}.log"
    res = _cur.execute("""SELECT timestamp, from_jid, message FROM `chatlogs` 
                          WHERE ((`from_jid` = :jid AND `to_jid` = :myjid) 
                          OR (`from_jid` = :myjid AND `to_jid` = :jid))
                          ORDER BY id""", {"jid": recipient, "myjid": _current_user})

    for bmsg in res.fetchall():
        try:
            msg = [x.decode("UTF-8", errors="backslashreplace") for x in bmsg]
        except Exception as e:
            msg = [x.decode("UTF-8", errors="replace") for x in bmsg]
        sender = "me" if msg[1] == _current_user else msg[1]
        msg_buffer.append(f"{msg[0]} - {sender}: {msg[2]}")

    tmpfpath.write_text('\n'.join(msg_buffer),
                        encoding="UTF-8", errors="replace")

    pid = os.fork()
    if pid == 0:
        os.execlp(_editor, _editor, str(tmpfpath))
    else:
        if pid == -1:
            return
        os.waitpid(pid, 0)
    prof.send_line("/statusbar show name")
    try:
        tmpfpath.unlink()
    except Exception as e:
        prof.log_error(
            f"[History Reader] Error on file deletion (path: {tmpfpath}): {e}")
    return


def prof_on_connect(account_name, fulljid):
    prof.log_debug(
        f"[History Reader] prof_on_connect called with this JID: {fulljid}")
    _init(fulljid)


def prof_on_disconnect(account_name, fulljid):
    prof.log_debug(
        f"[History Reader] prof_on_disconnect called with this JID: {fulljid}")
    global _current_user
    _current_user = ""


def prof_init(version, status, account_name, fulljid):
    prof.log_debug(
        f"[History Reader] prof_init called with this JID: {fulljid}")
    _init(fulljid)
    synopsis = ["/hh"]
    description = "Open an editor and check user's history."
    args = [
        ["set", "Set custom editor."]
    ]
    examples = [
        "/hh",
        "/hh set /usr/bin/vim",
        "/hh set gtk-open"
    ]
    prof.register_command("/hh", 0, 2, synopsis,
                          description, args, examples, _cmd_editor)
    prof.completer_add("/hh", ["set"])
    prof.filepath_completer_add("/hh set")


def _init(fulljid):
    global _current_user, _editor, _logs_dir, _db_file
    prof.log_debug(
        f"[History Reader] Initialization started with this JID: {fulljid}")
    _current_user = fulljid and fulljid.split('/')[0]
    if not _current_user:
        prof.log_debug(
            "[History Reader] Can't fetch current user, aborting initialization...")
        return
    _profanity_home = Path(os.getenv('XDG_DATA_HOME')
                           or "~/.local/share").expanduser() / "profanity"
    _logs_dir = _profanity_home / "chatlogs" / _str_sanitize(_current_user)
    db_dir = _profanity_home / "database" / _str_sanitize(_current_user)
    if not _logs_dir.is_dir():
        _show_error(f"Can't open logs directory. Path: {_logs_dir}")
        return
    if not db_dir.is_dir():
        _show_error(f"Can't open DB directory. Path: {db_dir}")
        return
    _db_file = db_dir / "chatlog.db"
    if not _db_file.is_file():
        _show_error(f"Log db is not present. Path: {_db_file}")
        return
    _editor = prof.settings_string_get("history", "editor", "")
    if not _editor:
        prof.cons_show("Please, set up editor using /hh set.")
    else:
        prof.cons_show(
            f"[History Reader] Successfully started. Editor: {_editor}")
