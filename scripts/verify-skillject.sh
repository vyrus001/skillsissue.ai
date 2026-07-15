#!/bin/sh
set -eu

expected="6598997b76044fa00abe0a4416064fbd2eab33ff"
actual="$(git -C SkillJect rev-parse HEAD)"
test "$actual" = "$expected"

skills="$(find SkillJect/data/skills_sample -name SKILL.md -type f | wc -l | tr -d ' ')"
attacks="$(find SkillJect/data/bash_scripts -type f \( -name '*.sh' -o -name '*.py' \) | wc -l | tr -d ' ')"
test "$skills" -eq 100
test "$attacks" -eq 77
printf 'SkillJect %s: %s skills, %s labeled attack scripts\n' "$actual" "$skills" "$attacks"
