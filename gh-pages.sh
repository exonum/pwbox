#!/bin/bash

# Copyright 2017 The Exonum Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

GH_DIR=.gh-pages
JS_URL=assets/js
MAIN_LIB=dist/pwbox-lite.min.js

# Cleanup
echo "Cleaning up $GH_DIR..."
rm -rf "$GH_DIR"

# Create target directories
mkdir -p "$GH_DIR/$JS_URL"

# Copy the HTML page
echo "Copying HTML..."
cp examples/demo.html "$GH_DIR/index.html"

# Copy the browser version of the library
[ -e "$MAIN_LIB" ] || npm run browser
cp "$MAIN_LIB" "$GH_DIR/$JS_URL"

echo "Editing HTML..."
FNAME=`basename "$MAIN_LIB"`
sed -r -i -e "s:(href|src)=\"../$MAIN_LIB\":\1=\"./$JS_URL/$FNAME\":" "$GH_DIR/index.html"

if [[ "x$1" == "xdeploy" ]]; then
  echo "Deploying to local gh-pages..."
  cd "$GH_DIR"
  git init && \
    git add . && \
    git commit -m "Deploy to GitHub Pages" && \
    git push --force --quiet "../.git" master:gh-pages && \
    rm -rf .git
  cd ..
fi
