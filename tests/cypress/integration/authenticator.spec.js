/*
 * Copyright 2022 Curity AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { registerCurityCommands } from "@curity/cypress-commands"

registerCurityCommands()

describe('GitHub Authenticator tests', () => {
  it('Verify that GitHub Authenticator properly initializes authorization request', () => {

    const parameters = {
      baseURL: 'https://localhost:8443/oauth/v2/oauth-authorize',
      clientID: 'oauth-assistant-client',
      redirectURI: 'http://localhost:8080/'
    }

    cy.startAuthorization(parameters)

    // Verify that GitHub has returned a login form
    cy.get('#login_field')
        .should('exist')
  })

})
