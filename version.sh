#!/bin/bash
###
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2018-2023 SCANOSS.COM
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
###
#
# Determine the latest tag associated with this repo and echo to stdout
#
version=$(git describe --tags --abbrev=0)
if [[ -z "$version" ]] ; then
  version=$(git describe --tags "$(git rev-list --tags --max-count=1)")
fi
if [[ -z "$version" ]] ; then
  echo "Error: Failed to determine a valid version number" >&2
  exit 1
fi
echo "$version" | sed 's/^v//'
exit 0