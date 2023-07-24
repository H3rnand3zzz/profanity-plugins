"""
Antispam plugin for profanity.
Asks a question from new contacts, thus verifying them.
"""

import math
import prof
import re
import datetime
from uuid import uuid4

# Constants
_antispam_defaults = {
    'msg': 'Please, solve the captcha',
    'question': 'Where a bullet must be lodged in order for rifle to shoot?',
    'answer': 'Chamber',
    'donemsg': 'You passed antispam. Congratulations!',
    'blockmsg': 'You\'ve been blocked. Try again {} minutes later',
    'errormsg': 'Wrong answer. Please, try again. The question is',
    'otrmsg': 'Please, turn off the OTR and then send the answer.',
    'unbanmsg': 'Your ban has been lifted. You can try again.',
    'maxtries': 5,
    'blocktime': 5,
    'debug': 'off',
    'dry': 'off'
}

_time_format = "%d.%m.%Y %H:%M:%S"

_roster = []

_page_limit = 10

_egg_counter = 0

_as_settings_strings = ['msg', 'question', 'answer', 'donemsg', 'blockmsg', 'otrmsg', 'errormsg', 'unbanmsg', 'debug', 'dry']
_as_settings_ints = {'maxtries': {'min': 2, 'max': 1000}, 'blocktime': {'min': -1, 'max': 100000}}
_as_settings = [*_as_settings_strings, *_as_settings_ints]


# Handlers

def prof_init(version, status, account_name, fulljid):
    synopsis = [
        "/antispam on|off",
        "/antispam settings",
        *[f"/antispam set {x} <msg>" for x in _as_settings_strings],
		"/antispam set maxtries <tries>",
		"/antispam set blocktime <minutes>",
		"/antispam counter [<page|clear>]",
		"/antispam history [<page|clear>]",
		"/antispam blocklist [<page>|add|remove <jid or part of jid>|clear]",
		"/antispam whitelist [<page>|add|remove <jid or part of jid>|clear]",
    ]
    description = "Prevents spam messages by asking new contacts questions."
    args = [
        [ "set msg <msg>",  "Set captcha message" ],
		[ "set question <msg>", "Set custom captcha question" ],
		[ "set answer <msg>", "Set answer to captcha question" ],
		[ "set donemsg <msg>", "Set congratulation message for passing antispam" ],
		[ "set blockmsg <msg>", "Set message that user is blocked. Use \"{}\" to show amounts of minutes before unlock. Example: You are banned. Unban in {} minutes." ],
		[ "set otrmsg <msg>", "Set answer in case if unauthorized user tries to initiate OTR session." ],
		[ "set errormsg <msg>", "Set prefix to answer in case if wrong answer given." ],
		[ "set unbanmsg <msg>", "Set message given when temporary ban is finished. Set to \"None\" to prevent sending message." ],
		[ "set maxtries <tries>", "Set maximum amount of tries before ban. Set -1 to make unlimited." ],
		[ "set blocktime <minutes>", "Set time to block user for. Set -1 to make ban unlimited." ],
		[ "set debug <on|off>", "Set debug mode on|off." ],
		[ "set dry <on|off>", "Set dry mode on|off. In dry mode antispam doesn't block messages, mode is needed for debug use." ],
		[ "counter [<page>|clear]", "Show or clear wrong answer counter" ],
		[ "history [<page>|clear]", "Show or clear history" ],
		[ "blocklist [add|remove <jid or part of jid>|clear]", "Show banned users, or add|remove user from ban" ],
		[ "whitelist [add|remove <jid or part of jid>|clear]", "Whitelist users. Whitelist have priority over bans." ],
    ]
    examples = [
        "/antispam on",
		"/antispam set msg Please, solve the captcha.",
		"/antispam set question 2 + 2? (1984)",
		"/antispam set answer 5",
		"/antispam set donemsg You passed antispam. Now your messages are delivered.",
		"/antispam set blockmsg You've been blocked by antispam. Please, try again later in {} minute(s).",
		"/antispam set maxtries 5",
		"/antispam set blocktime 69",
		"/antispam blocklist clear",
		"/antispam history 42",
    ]

    prof.register_command("/antispam", 1, 40, synopsis, description, args, examples, _cmd_antispam)

    prof.register_command("/as", 1, 40, _prep_alias(synopsis), description, args, _prep_alias(examples), _cmd_antispam)

    prof.completer_add("/antispam", 
        [ "set", "history", "blocklist", "whitelist" ]
    )

    prof.completer_add("/antispam set",
        _as_settings
    )
    prof.completer_add("/antispam history", 
        [ 'clear' ]
    )

    prof.completer_add("/antispam blocklist",
        [ 'add', 'remove', 'clear' ]
    )

    prof.completer_add("/antispam whitelist",
        [ 'add', 'remove', 'clear' ]
    )

    prof.register_timed(_update_banned_list, 60)

    _force_update_roster((fulljid.split('/')[0] if fulljid else ''))

    prof.cons_show("[AntiSpam] plugin started.")
    if _is_dry_mode():
        prof.cons_show("[AntiSpam] WARNING: dry-mode is on, no messages are going to be blocked.")

def prof_on_message_stanza_send(stanza):
    body = _parse_tag_content(stanza, 'body')
    if body and (to := _parse_attr(stanza, 'to').split('/', 1)[0]):
        if not _is_authorized(to):
            prof.settings_string_list_add("antispam", "authorized", to)
    return stanza

def prof_on_presence_stanza_send(stanza):
    if _parse_attr(stanza, 'type') == 'subscribe' and (to := _parse_attr(stanza, 'to').split('/', 1)[0]):
        if not _is_authorized(to):
            prof.settings_string_list_add("antispam", "authorized", to)
    return stanza


def prof_on_message_stanza_receive(stanza) -> bool:
    return _antispam_check_wrapper(stanza, 'msg')

def prof_on_presence_stanza_receive(stanza) -> bool:
    return _antispam_check_wrapper(stanza, 'presence')

def prof_on_iq_stanza_receive(stanza) -> bool:
    if 'jabber:iq:roster' in stanza and 'type="result"' in stanza:
        _update_roster(stanza)
    return _antispam_check_wrapper(stanza, 'iq')

# Custom functions

def _cmd_antispam(*args):
    if not len(args):
        _show_cmd_error()
    if args[0] == "on":
        prof.settings_boolean_set("antispam", "enabled", True)
        prof.cons_show("Antispam is enabled.")
        return
    if args[0] == "off":
        prof.settings_boolean_set("antispam", "enabled", False)
        prof.cons_show("Antispam is disabled.")
        return
    if args[0] == "set":
        if len(args) < 3:
            _show_cmd_error('More arguments required')
            return
        key = args[1]
        if key not in _as_settings:
            _show_cmd_error(f'Wrong setting. You can use only {_as_settings}')
            return
        if args[2] == "default":
            _set_default_values(key)
            return
        if _set_values(key, args[2:]):
            prof.cons_show(f'Antispam setting {key} was successfully changed to "{" ".join(args[2:])}"')
        else:
            _show_cmd_error("Something went wrong, setting wasn't changed")
        return
    if args[0] == "settings":
        prof.cons_show("===== Antispam settings =====")
        for key in _as_settings:
            value = _get_string_setting(key) if key in _as_settings_strings else _get_int_setting(key)
            fvalue = f'"{value}"' if key in _as_settings_strings else value
            prof.cons_show(f'{key} is {fvalue}')
        return
    if args[0] in ["counter", "history", "authorized"]:
        return _cmd_show_or_clear(args)
    if args[0] == "blocklist":
        return _cmd_as_blocklist(args)
    if args[0] == "whitelist":
        return _cmd_as_whitelist(args)
    if args[0] == "egg":
        global _egg_counter
        if _egg_counter == 10:
            prof.cons_show(f"Do you know that it's an antispam plugin and not an egg farm? No more eggs for you!")
            return
        _egg_counter += 1
        prof.cons_show(f"Egg number {_egg_counter} has been planted.")
        if _egg_counter == 5:
            prof.cons_show(f"What do you need so many eggs for?")
        return
    if args[0] == "roster":
        prof.cons_show("\n".join(_roster))
        return
    prof.cons_bad_cmd_usage('/antispam')

def _cmd_show_or_clear(args):
    if len(args) == 1:
        return _show_page(args[0])
    if len(args) == 2:
        if args[1] == "clear":
            if prof.settings_string_list_clear("antispam", args[0]):
                prof.cons_show(f'{args[0].capitalize()} has been cleared.')
            else:
                prof.cons_show(f'{args[0].capitalize()} is already empty.')
            return
        return _show_page(args[0], args[1])
    prof.cons_bad_cmd_usage('/antispam')

def _cmd_as_blocklist(args):
    if len(args) < 3:
        return _cmd_show_or_clear(args)
    if args[1] == "add":
        for jid in args[2:]:
            ban_time = _ban_user(jid, full_jid=False, time_limited=False)
            prof.cons_show(f'JID "{jid}" has been banned {ban_time}.')
    elif args[1] == "remove":
        for jid in args[2:]:
            if _unban_user(jid):
                prof.cons_show(f'JID "{jid}" has been unbanned.')
            else:
                prof.cons_show(f'JID "{jid}" has not been found in the blocklist.')

def _cmd_as_whitelist(args):
    if len(args) < 3:
        return _cmd_show_or_clear(args)
    if args[1] == "add":
        for jid in args[2:]:
            prof.settings_string_list_add("antispam", "whitelist", jid)
            prof.cons_show(f'JID "{jid}" has been whitelisted.')
    elif args[1] == "remove":
        for jid in args[2:]:
            if prof.settings_string_list_remove("antispam", "whitelist", jid):
                prof.cons_show(f'JID "{jid}" has been removed from the whitelist.')
            else:
                prof.cons_show(f'JID "{jid}" has not been found in the whitelist.')

def _show_cmd_error(error="", user_mistake=True) -> None:
    """Used to shows str:error when user typed wrong input"""
    if user_mistake:
        prof.cons_bad_cmd_usage('/antispam')
    if error:
        prof.cons_show(error)


def _set_default_values(key) -> bool:
    default_value = _antispam_defaults[key]
    if (key in _as_settings_strings):
        prof.settings_string_set("antispam", key, default_value)
    elif (key in _as_settings_ints):
        prof.settings_int_set("antispam", key, default_value)
    prof.cons_show(f'Antispam setting {key} was successfully set to its default ({default_value}).')

def _set_values(key, value) -> bool:
    """Returns Bool True if values has been set, False is value is invalid"""
    value = ' '.join(value)
    if key in _as_settings_strings:
        prof.settings_string_set("antispam", key, value)
        return True
    if key in _as_settings_ints:
        min_val, max_val = _as_settings_ints[key]['min'], _as_settings_ints[key]['max']
        if not _represents_int_in_range(value, min_val, max_val):
            prof.cons_show(f'Value of {key} must be an integer between {min_val} and {max_val}!')
            return False
        prof.settings_int_set("antispam", key, int(value))
        return True
    return False

def _parse_tag_content(stanza, tag):
    tmp = re.search(f"<{tag}.*?>([\S\s]*?)</{tag}>", stanza) # don't blame me, it works :D
    try:
        return tmp.group(1) if tmp else ""
    except IndexError as e:
        return ""

def _parse_attr(stanza, attribute) -> str:
    """Parse attribute from the first tag"""
    tmp = re.search(f'^\s*<[^>]+{attribute}="([^"]+)"', stanza)
    try:
        return tmp.group(1) if tmp else ""
    except IndexError as e:
        return ""

def _parse_sender(stanza) -> str:
    """Returns sender from stanza or empty string if not found"""
    if "<forwarded" in stanza:
        stanza = _parse_tag_content(stanza, "forwarded")
    return _parse_attr(stanza, "from").split('/', 1)[0]

def _parse_id(stanza) -> str:
    """Returns id from stanza or empty string if not found"""
    return _parse_attr(stanza, "id")

def _is_dry_mode() -> bool:
    return _get_string_setting("dry") == "on"

def _antispam_check_wrapper(stanza, stanza_type) -> bool:
    result = _antispam_check(stanza, stanza_type)
    dry_mode = _is_dry_mode()
    if not result:
        if _get_string_setting("debug") == "on" or dry_mode:
            prof.cons_show(f"[AntiSpam{' (DryMode)' if dry_mode else ''}] Blocked stanza: {stanza}")
        else:
            prof.log_debug(f"[AntiSpam] Blocked stanza: {stanza}")
    return result or _is_dry_mode()

def _antispam_check(stanza, stanza_type) -> bool:
    """Returns Bool True if message is not spam, False if message should be blocked (spam/unverified sender)"""
    sender = _parse_sender(stanza)
    stanza_id = _parse_id(stanza)
    if not sender and "from=" in stanza:
        prof.log_warning(f"In the following stanza From is present, but not catched: \n{stanza}")
    if not _is_activated():
        return True
    if _is_whitelisted(sender) or _is_in_roster(sender):
        return True
    if _is_banned(sender):
        return False
    if _is_authorized(sender):
        return True
    if not _roster:
        prof.log_debug(f"[AntiSpam] Passed message because roster was empty. Stanza: {stanza}")
        return True
    if stanza_type == "presence":
        if re.search('^\s*<presence.+type="subscribe".+>', stanza):
            _send_stanza(f'<presence type="unsubscribed" to="{sender}" />')
            _send_stanza(f'<message type="chat" to="{sender}"><subject>{_get_string_setting("msg")}</subject><body>{_get_string_setting("question")}</body></message>')
            _counter_inc(sender)
    elif stanza_type == "iq":
        if re.search('^\s*<iq[^>]+type="set"', stanza):
            to = f'to="{sender}" ' if sender else ''
            _send_stanza(f'<iq type="error" id="{stanza_id}" {to}/>')
            return False
        return True
    elif stanza_type == "msg":
        if _parse_attr(stanza, "type") == "error":
            prof.settings_string_list_add("antispam", "history", f"{_get_time()}|{sender}|{_parse_tag_content(stanza, 'body')}")
            return False
        if not _is_correct_answer(stanza):
            if (is_otr_requested := "OTRv2" in stanza):
                _send_stanza(f'<message type="chat" to="{sender}"><body>{_get_string_setting("otrmsg")}</body></message>')
            prof.settings_string_list_add("antispam", "history", f"{_get_time()}|{sender}|{_parse_tag_content(stanza, 'body')}")
            wrong_tries = _get_counter(sender)
            subject = f'<subject>{_get_string_setting("msg")}</subject>' if wrong_tries == 0 else ''
            wrong_answer = _get_string_setting("errormsg")+'\n' if wrong_tries > 0 and not is_otr_requested else ''
            _send_stanza(f'<message type="chat" to="{sender}">{subject}<body>{wrong_answer}{_get_string_setting("question")}</body></message>')
            _counter_inc(sender)
            return False
        prof.settings_string_list_add("antispam", "authorized", sender)
        _send_stanza(f'<message type="chat" to="{sender}"><body>{_get_string_setting("donemsg")}</body></message>')
    return False

def _force_update_roster(myjid=None) -> None:
    global _roster
    if not _roster and myjid:
        _roster = [myjid]
    prof.send_stanza(f'<iq id="{uuid4()}" type="get"><query xmlns="jabber:iq:roster"/>\</iq>')
    return

def _update_roster(stanza) -> None:
    global _roster
    _roster = [
        *re.findall('<iq[^>]+to="([^"/]+)["/]', stanza),
        *[x for x,y in re.findall('<item[^>]+jid="([^"]+?)"[^>]+subscription="([^"]+?)"', stanza) if y == "both" or y == "to"],
        *[x for y,x in re.findall('<item[^>]+subscription="([^"]+?)"[^>]+jid="([^"]+?)"', stanza) if y == "both" or y == "to"],
    ]
    

def _is_activated() -> bool:
    return prof.settings_boolean_get("antispam", "enabled", True)

def _update_banned_list() -> None:
    ban_list = prof.settings_string_list_get("antispam", "blocklist") or []
    for banned_user in ban_list:
        if not (tmp := _unpack_banned_user(banned_user)):
            continue
        ban_time, ban_type, jid = tmp
        if ban_time != "Forever" and not _is_future_time(ban_time):
            unbanmsg = _get_string_setting("unbanmsg")
            if unbanmsg != "None":
                _send_stanza(f'<message type="chat" to="{jid}"><body>{unbanmsg}</body></message>')
            prof.settings_string_list_remove("antispam", "blocklist", banned_user)
    return

def _unpack_banned_user(banned_user):
    """Returns None or Tuple of banned user info in (time_banned, ban_type, jid) format"""
    tmp = banned_user.split("|", 2)
    if len(tmp) != 3:
        prof.cons_show(f"Problem on banned user unpacking: \"{banned_user}\". Deleting...")
        prof.settings_string_list_remove("antispam", "blocklist", banned_user)
        return
    return tmp
    
def _is_in_roster(jid) -> bool:
    return jid in _roster
    
def _is_authorized(jid) -> bool:
    return jid in (prof.settings_string_list_get("antispam", "authorized") or [])

def _is_banned(jid) -> bool:
    ban_list = prof.settings_string_list_get("antispam", "blocklist") or []
    for banned_user in ban_list:
        if not (tmp := _unpack_banned_user(banned_user)):
            continue
        ban_time, ban_type, bjid = tmp
        if ban_type == "F": # On full JID ban (e.g. "user@example.com")
            if jid == bjid and (ban_time == "Forever" or _is_future_time(ban_time)):
                return True
        else: # On partial JID ban (e.g. "@example.com", "spammer")
            if bjid in jid and (ban_time == "Forever" or _is_future_time(ban_time)):
                return True
    return False

def _is_whitelisted(jid) -> bool:
    wl_users = (prof.settings_string_list_get("antispam", "whitelist") or [])
    return any(wj in jid for wj in wl_users)

def _get_validate_count(c):
    tmp = c.split('|', 1)
    if len(tmp) != 2:
        prof.log_warning(f'Invalid counter entry: "{c}". Removing...')
        prof.settings_string_list_remove("antispam", "counter", c)
        return
    return int(tmp[0]), tmp[1]

def _counter_inc(jid) -> None:
    counter = prof.settings_string_list_get("antispam", "counter") or []
    for c in counter:
        if not (tmp := _get_validate_count(c)): 
            continue
        count, cjid = tmp
        if jid == cjid:
            prof.settings_string_list_remove("antispam", "counter", c)
            prof.settings_string_list_add("antispam", "counter", f"{count+1}|{jid}")
            if count % _get_int_setting("maxtries") == 0:
                ban_time = _ban_user(jid)
                blockmsg = _get_string_setting("blockmsg").replace('{}', str(ban_time))
                _send_stanza(f'<message type="chat" to="{jid}"><body>{blockmsg}</body></message>')
            return
    prof.settings_string_list_add("antispam", "counter", f"1|{jid}")


def _get_counter(jid) -> int:
    counter = prof.settings_string_list_get("antispam", "counter") or []
    for c in counter:
        if not (tmp := _get_validate_count(c)): 
            continue
        count, cjid = tmp
        if jid == cjid:
            return count
    return 0

def _show_page(table, page_num=1) -> None:
    """Shows a page from table N (table is fetched from string_list setting with name) to plugin user through cons_show."""
    if not _represents_int_in_range(page_num, 1):
        prof.cons_show("Use correct page number. It must be integer from 1 to 10000.")
        return
    page_num = int(page_num)
    page = page_num-1
    table_content = prof.settings_string_list_get("antispam", table) or []
    table_size = len(table_content)
    total_pages = math.ceil(table_size/_page_limit)
    if not table_content:
        return prof.cons_show(f"Nothing to display, {table} is empty")
    if page_num > total_pages:
        return prof.cons_show(f"Page {page_num} does not exist. There are only {total_pages} pages")
    page_content = table_content[page*_page_limit:page_num*_page_limit]
    if not page_content:
        return prof.cons_show(f"Nothing to display, {table} on Page {page_num} is empty")
    for x in page_content:
        formatting = (lambda x: x)
        prof.cons_show(formatting(x))
    prof.cons_show(f"Page {page_num}/{total_pages}. Currently {table_size} entries.")

def _ban_user(jid, full_jid=True, time_limited=True, custom_time_limit=None):
    """Adds user to ban list"""
    ban_type = "F" if full_jid else "P"
    if time_limited and (ban_time := custom_time_limit if custom_time_limit else _get_int_setting("blocktime")) != -1:
        ban_time_formatted = (datetime.datetime.now() + datetime.timedelta(minutes=ban_time)).strftime("%d.%m.%Y %H:%M:%S")
        _unban_user(jid)
        prof.settings_string_list_add("antispam", "blocklist", f"{ban_time_formatted}|{ban_type}|{jid}")
        return ban_time
    prof.settings_string_list_add("antispam", "blocklist", f"Forever|{ban_type}|{jid}")
    return "forever"

def _unban_user(jid):
    """Removes user from ban list. True on success, otherwise false."""
    ban_list = prof.settings_string_list_get("antispam", "blocklist") or []
    for banned_user in ban_list:
        if not (tmp := _unpack_banned_user(banned_user)):
            continue
        ban_time, ban_type, bjid = tmp
        if bjid == jid:
            return prof.settings_string_list_remove("antispam", "blocklist", banned_user)
    return False


# Settings utils

def _get_string_setting(setting) -> str:
        return prof.settings_string_get("antispam", setting, _antispam_defaults[setting])

def _get_int_setting(setting) -> int:
        return prof.settings_int_get("antispam", setting, _antispam_defaults[setting])

# Utils

def _prep_alias(replace_list):
    return [x.replace("/antispam", "/as") for x in replace_list]

def _is_correct_answer(stanza):
    correct_answer = _get_string_setting('answer')
    answer = _parse_tag_content(stanza, "body")
    if not answer:
        prof.log_warning(f'Invalid mesage stanza. Ignoring user input. Stanza: {stanza}')
        return False
    return answer.strip().lower() == correct_answer.strip().lower()

def _is_future_time(time) -> bool:
    """Checks formatted time and returns True if time from parameter is in the future"""
    try:
        ptime = datetime.datetime.strptime(time, _time_format)
    except ValueError as e:
        prof.log_error(f"Exception raised when time was compared (input time: {time})\n{e}")
        return True
    return ptime > datetime.datetime.now() 

def _get_time():
    """Returns current time formatted"""
    return datetime.datetime.now().strftime(_time_format)

def _represents_int_in_range(s, num_min=-1, num_max=10000) -> bool:
    """Returns True if passed number is integer and it is in provided range (from -1 to 10000 by default)"""
    try: 
        num = int(s)
        return num >= num_min and num <= num_max
    except ValueError:
        return False
    else:
        return True

def _send_stanza(stanza):
    if not _is_dry_mode():
        return prof.send_stanza(stanza)
        
