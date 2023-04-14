"""Profanity plugin that provides anonimity tips."""
import prof
import random

# Credits to https://www.whonix.org/wiki/Tips_on_Remaining_Anonymous
tips = [
  "Refrain from including personal information or interests in nicknames.",
  "Refrain from discussing personal information like location, age, marital status and so on. Over time, discussions about something trivial like the weather could lead to an accurate idea of the user's location.",
  "Refrain from mentioning one's gender, tattoos, piercings, physical capacities or disabilities.",
  "Refrain from mentioning one's profession, hobbies or involvement in activist groups.",
  "Refrain from using special characters on the keyboard which only exist in your language.",
  "Refrain from posting information to the regular internet (clearnet) while anonymous.",
  "Refrain from using Twitter, Facebook and other social network platforms. This is easy to correlate.",
  "Refrain from posting links to Facebook and Discord images. The image name contains a personal ID.",
  "Refrain from connecting to same destination at the same time of the day or night. Try to vary connection times.",
  "Refrain from forgetting that IRC, other chats, forums, mailing lists and so on are public arenas.",
  "Refrain from discussing anything personal whatsoever, even when securely and anonymously connecting to a group of strangers.\nThe group recipients are a potential hazardous risk (\"known unknowns\") and could have been forced to work against the user.\nIt only takes one informant to destroy a group.",
  "Refrain from using software with compulsory telemetry.",
  "Always go the Extra Mile with Security.",
  "Use BIOS password.",
  "Use full-disk encryption.",
  "Avoid posting full system logs or full configuration files.",
  "Avoid posting sensitive screenshots, recordings and photographs.",
  "Send sensitive data ONLY WITH End-to-End encryption.",
  "Only use ONE online pseudonym at the same time. Use different nicknames for different services.",
  "Avoid (Mobile) phone verification.",
  "Only connect to a server either anonymously or non-anonymously.",
  "Be wary of random files or links.",
  "Behave like most other users on your websites.",
  "Exceptions for online banking and online payment accounts.",
  "Be aware that social networks most often Know Who You Are.",
  "Always log out from Twitter, Facebook, Google etc.",
  "Change settings only if the consequences are known.",
  "Refrain from \"Tor over Tor\" scenarios.",
  "Do use bridges if tor is deemed dangerous or suspicious in your location.",
  "Respect privacy of others.",
  "Your anonimity is measured by the strength of its weakest link.",
  "Use privacy addons on your browser, such as uBlock Origin.",
  "Use privacy-friendly software and OS. Most Linux distros, Tor Browser, LibreWolf or Degoogled Chromium and Profanity for communication.",
  "Encrypt everything. Files (full disk encryption), RAM (hardware encryption), connection (httpS), messages (E2E).",
  "Use password manager, generate hard passwords. You will have to remember only master password and make periodical backups.",
  "Make backups. Make backups. And, yes, make backups. Don't forget to secure them, there is almost no point in encryption if your backups are in plain format.",
  "Check fingerprints of your recipient."
]

def prof_init(*args, **kwargs):
    prof.cons_show(f"Security tip: {random.choice(tips)}")
