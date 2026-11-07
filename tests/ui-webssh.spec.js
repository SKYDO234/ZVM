/* Real browser + WebSocket + SSH protocol/PTY fixture. No OS/VM claim. */
const {test, expect} = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const state = () => JSON.parse(fs.readFileSync(path.join(__dirname, '../test-results/.webssh-credentials.json'), 'utf8'));
async function openPage(page, project) {
  const fixtures = state(), account = fixtures.accounts[project];
  await page.goto('/login');
  await page.locator('[name=email]').fill(account.email);
  await page.locator('[name=password]').fill(account.password);
  await page.getByRole('button', {name: 'Sign in to workspace'}).click();
  await page.waitForURL('**/dashboard');
  await page.goto('/webssh/' + account.instance);
  await expect(page.locator('#ssh-connect')).toBeEnabled();
  await expect(page.locator('#ssh-status')).toHaveText('Disconnected');
  return fixtures;
}
async function acceptKey(page, fixtures) {
  // A previous test can already have trusted the key in this disposable DB.
  await expect.poll(async () => (await page.locator('#ssh-trust-dialog').isVisible()) || (await page.locator('#ssh-status').textContent()) === 'Connected').toBeTruthy();
  if (await page.locator('#ssh-trust-dialog').isVisible()) {
    await expect(page.locator('#ssh-key-fingerprint')).toHaveText(fixtures.fingerprint);
    await page.locator('#ssh-accept-key').click();
  }
  await expect(page.locator('#ssh-status')).toHaveText('Connected');
  await expect(page.locator('#ssh-rtt')).toHaveText(/RTT \d+ ms/);
}
async function typeIntoTerminal(page, text) {
  await page.locator('.xterm-helper-textarea').focus();
  await page.keyboard.type(text);
  await page.keyboard.press('Enter');
}

test('password SSH terminal, host fingerprint, measured RTT, input, resize, special keys, clear and disconnect', async ({page}, testInfo) => {
  const errors = [], terminalInputs = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('websocket', ws => ws.on('framesent', frame => {
    const data = JSON.parse(frame.payload.toString());
    if (data.type === 'input') terminalInputs.push(data.data);
  }));
  const fixtures = await openPage(page, testInfo.project.name);
  await page.locator('#ssh-connect').click();
  await page.locator('#ssh-password').fill(fixtures.guest_password);
  await page.getByRole('button', {name: 'Connect to guest', exact: true}).click();
  await acceptKey(page, fixtures);
  await expect(page.locator('#ssh-password')).toHaveValue('');
  await expect(page.locator('#ssh-terminal')).toContainText('SSH protocol fixture ready');
  const marker = 'ui-ssh-' + crypto.randomBytes(5).toString('hex');
  await typeIntoTerminal(page, marker);
  await expect(page.locator('#ssh-terminal')).toContainText(marker);
  await page.getByRole('button', {name: 'Send Control C'}).click();
  await expect(page.locator('#ssh-terminal')).toContainText('CONTROL-C received');
  if (testInfo.project.name === 'webssh-desktop') {
    const before = await page.locator('#ssh-size').textContent();
    await page.setViewportSize({width: 1100, height: 820});
    await expect(page.locator('#ssh-size')).not.toHaveText(before);
  }
  await typeIntoTerminal(page, '__fixture_size__');
  await expect(page.locator('#ssh-terminal')).toContainText('PTY dimensions:');
  const dimensions = (await page.locator('#ssh-size').textContent()).replace(' × ', 'x');
  await expect(page.locator('#ssh-terminal')).toContainText('PTY dimensions: ' + dimensions);
  const inputsBeforeClear = terminalInputs.length;
  await page.locator('#ssh-clear').click();
  await expect(page.locator('#ssh-terminal')).not.toContainText(marker);
  await expect(page.locator('#ssh-terminal .live-region')).toHaveText('');
  expect(terminalInputs.length).toBe(inputsBeforeClear); // Local view only, no guest command.
  await page.locator('#ssh-disconnect').click();
  await expect(page.locator('#ssh-status')).toHaveText('Disconnected');
  await expect(page.locator('#ssh-connect')).toBeEnabled();
  await expect(page.locator('#ssh-disconnect')).toBeDisabled();
  await expect(page.locator('#ssh-rtt')).toHaveText('RTT —');
  await page.locator('#ssh-connect').click();
  await expect(page.locator('#ssh-password')).toHaveValue('');
  await page.locator('#ssh-auth-back').click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  expect(await page.evaluate(() => Object.keys(localStorage).filter(key => /ssh|password|private.?key|token/i.test(key)))).toEqual([]);
  expect(errors).toEqual([]);
});

test('encrypted private key upload authenticates without persisting key material', async ({page}, testInfo) => {
  const fixtures = await openPage(page, testInfo.project.name);
  await page.locator('#ssh-connect').click();
  await page.locator('#ssh-auth-method').selectOption('key');
  await page.locator('#ssh-key-file').setInputFiles({name: 'disposable-test.key', mimeType: 'text/plain', buffer: Buffer.from(fixtures.private_key)});
  await expect(page.locator('#ssh-private-key')).toHaveValue(fixtures.private_key);
  await page.locator('#ssh-key-passphrase').fill(fixtures.passphrase);
  await page.getByRole('button', {name: 'Connect to guest', exact: true}).click();
  await acceptKey(page, fixtures);
  await expect(page.locator('#ssh-private-key')).toHaveValue('');
  await expect(page.locator('#ssh-key-passphrase')).toHaveValue('');
  await page.locator('#ssh-disconnect').click();
  await expect(page.locator('#ssh-status')).toHaveText('Disconnected');
});

test('wrong guest credentials fail honestly, and closing a key dialog clears secrets', async ({page}, testInfo) => {
  const fixtures = await openPage(page, testInfo.project.name);
  await page.locator('#ssh-connect').click();
  await page.locator('#ssh-password').fill('incorrect-disposable-guest-password');
  await page.getByRole('button', {name: 'Connect to guest', exact: true}).click();
  await expect.poll(async () => (await page.locator('#ssh-trust-dialog').isVisible()) || (await page.locator('#ssh-alert').isVisible())).toBeTruthy();
  if (await page.locator('#ssh-trust-dialog').isVisible()) await page.locator('#ssh-accept-key').click();
  await expect(page.locator('#ssh-alert')).toContainText('authentication failed');
  await expect(page.locator('#ssh-status')).not.toHaveText('Connected');
  await expect(page.locator('#ssh-connect')).toBeEnabled();
  await page.locator('#ssh-connect').click();
  await page.locator('#ssh-auth-method').selectOption('key');
  await page.locator('#ssh-private-key').fill(fixtures.private_key);
  await page.locator('#ssh-auth-back').click();
  await expect(page.locator('#ssh-private-key')).toHaveValue('');
});
