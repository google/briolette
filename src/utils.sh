#!/bin/bash
# Copyright 2023 The Briolette Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# To use:
#  source utils.sh

clear_data() {
for dir in $(ls -F data/ | grep /); do
    (rm $dir/* || true) &>/dev/null
done
}

run_cmd_at() {
        name="$1"
        t="$2"
        echo "Starting $t in $name..."
        cargo run --bin briolette-${name}-${t} &
        sleep 1
}

run_server() {
        run_cmd_at "$1" server
}

run_client() {
        run_cmd_at "$1" client
}


start_servers() {
        run_server registrar
        run_client registrar
        run_server clerk
        run_server tokenmap
        run_server mint

        run_cmd_at clerk generate-epoch
        sleep 5 

        run_server validate
        run_server swapper
        run_server receiver

        run_client receiver

	# run_client swapper
}

kill_bg() {
        kill $(jobs -p)
}
