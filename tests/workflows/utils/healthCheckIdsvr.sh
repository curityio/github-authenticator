#!/bin/bash

##
# Copyright 2022 Curity AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

sleepTime=2
i=0
while [ $i -lt $WAIT_TIMEOUT ] && [ "$(curl -k -s -o /dev/null -w ''%{http_code}'' -u "$ADMIN_USER:$ADMIN_PASSWORD" "https://localhost:6749/admin/api/restconf/data?content=config")" != "200" ]; do
   (( i += $sleepTime ))
  sleep $sleepTime
done

if [ $i -ge $WAIT_TIMEOUT ]; then
  echo "The Curity Identity Server did not start in expected time."
  exit 1
fi
