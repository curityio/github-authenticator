/*
 * Copyright 2021 Curity AB
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

export function updateStringSetting(setting, settingValue) {
    replaceSetting(`"${setting}":\\s+"[^"]+"`, `"${setting}": "${settingValue}"`)
}

export function replaceSetting(pattern, replacement) {
    cy.get('#authorizeSettings').invoke('val').then(value => {
        value = value.replace(new RegExp(pattern), replacement);
        cy.get("#authorizeSettings").invoke('val', value).trigger('change');
    });
}

export function inputText(selector, text) {
    cy.get(selector)
        .click({ force: true })
        .clear()
        .type(text)
}

export function clickElement(selector, apiCall = false, clickOptions = null) {
    cy.get(selector)
        .should('exist')
        .click(clickOptions)
}

function getHTMLBodyAsJQueryDOM(body) {
    return Cypress.$(body)
}
