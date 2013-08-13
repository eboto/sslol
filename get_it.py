import sys
import urllib2
import json
import fileinput
import os
import os.path
import subprocess

def api(route):
    response = urllib2.urlopen('https://api.github.com%s' % route).read()
    return json.loads(response)


def get_version_str(ref):
    return ref["ref"].split("/")[-1]


def get_from_user(prompt, default, validate):
    result = None
    while result is None:
        user_entered_data = raw_input(prompt + " [%s] " % default)
        if not user_entered_data:
            result = default
        elif validate(user_entered_data):
            result = user_entered_data

    return result

refs = api("/repos/eboto/sslol/git/refs")
versions = [ref for ref in refs if "tags/v" in ref["ref"]] # lol

versions.sort(key=lambda v: v["ref"])
versions.reverse()

king = versions[0]

print "SSLOL Versions:"

for version in versions:
    version_str = get_version_str(version)
    print "\t%s" % version_str,

    if version is king:
        print " (most recent)"
    else:
        print ""

user_version = None

while user_version is None:
    inputted_version = raw_input("Get which version? [%s] " % get_version_str(king))
    if not inputted_version:
        user_version = king
    else:
        try:
            user_version = next(ver for ver in versions if get_version_str(ver) == inputted_version)
        except StopIteration:
            print "\tEnter a version from the list above"
            pass

version_str = get_version_str(user_version)
print "Gonna get version %s" % get_version_str(user_version)
print ""

filename = "SSLOL-%s.scala" % version_str
current_dir = os.getcwd()


def validate_dir(dir):
    result = os.path.isdir(dir)
    if not result:
        print "Valid directory if you please!\n"
    return result

target_dir = get_from_user("Where to put %s?" % filename, current_dir, validate_dir)
target_file_spec = "%s/%s" % (target_dir, filename)

subprocess.call(["curl", "https://raw.github.com/eboto/sslol/%s/SSLOL.scala", "--output", target_file_spec])
