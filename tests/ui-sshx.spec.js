// Browser integration against a marked synthetic SSH protocol fixture, NOT VM/relay acceptance.
const {test, expect} = require('@playwright/test');
const fs = require('fs');
const state = () => JSON.parse(fs.readFileSync('test-results/.sshx-ui-credentials.json','utf8'));
async function login(page, account, other=false){
  await page.goto('/login');
  await page.locator('[name=email]').fill(other?account.other_email:account.email);
  await page.locator('[name=password]').fill(account.password);
  await page.getByRole('button',{name:'Sign in to workspace'}).click();
  await page.waitForURL('**/user');
}

test('owner generates protocol output link on Details, copies and stops; other user is denied', async ({page,browser},info)=>{
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const account=state()[info.project.name];
  await login(page,account);await page.goto(`/vps/${account.managed_id}#sshx`);
  await expect(page.locator('#sshx-link')).toHaveCount(0);
  await page.getByRole('button',{name:'Generate SSHX',exact:true}).click();
  await page.locator('#accept-confirm').click();
  const expected=`https://sshx.io/s/ui-protocol-${account.managed_id.replaceAll('-','')}#SyntheticUIKey0001`;
  await expect(page.locator('#sshx-link')).toHaveText(expected,{timeout:20000});
  const open=page.locator('#open-sshx');
  await expect(open).toHaveAttribute('href',expected);
  await expect(open).toHaveAttribute('target','_blank');
  await expect(open).toHaveAttribute('rel','noopener noreferrer');
  await expect(open).toHaveAttribute('referrerpolicy','no-referrer');
  await page.context().grantPermissions(['clipboard-read','clipboard-write']);
  await page.getByRole('button',{name:'Copy SSHX link'}).click();
  expect(await page.evaluate(()=>navigator.clipboard.readText())).toBe(expected);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  const context=await browser.newContext(), outsider=await context.newPage();
  await login(outsider,account,true);
  expect((await outsider.goto(`/vps/${account.managed_id}`)).status()).toBe(404);
  expect((await outsider.request.get(`/api/vps/${account.managed_id}/metrics`)).status()).toBe(404);
  expect(await outsider.content()).not.toContain(expected);
  await context.close();
  await page.getByRole('button',{name:'Stop SSHX',exact:true}).click();
  await page.locator('#accept-confirm').click();
  await expect(page.locator('#sshx-link')).toHaveCount(0,{timeout:20000});
  await expect(page.locator('[data-no-sshx-link]')).toBeVisible();
  await verifyPollingRecovery(page,account);
  expect(errors).toEqual([]);
});

test('existing guest enrollment verifies fingerprint and new key without reinstall', async ({page},info)=>{
  const account=state()[info.project.name];
  await login(page,account);await page.goto(`/vps/${account.enroll_id}`);
  await expect(page.getByRole('button',{name:'Generate SSHX',exact:true})).toBeDisabled();
  await page.getByRole('link',{name:'Enroll existing VM',exact:true}).click();
  await expect(page.locator('#guest-host-fingerprint')).toHaveText(/^SHA256:[A-Za-z0-9+/]{43}$/);
  await page.locator('#enroll-method').selectOption('key');
  await expect(page.locator('[name=private_key]')).toBeEnabled();
  await expect(page.locator('[name=guest_password]')).toBeDisabled();
  await page.locator('[name=private_key]').fill('unused fixture value must not be submitted');
  await page.locator('#enroll-method').selectOption('password');
  await expect(page.locator('[name=private_key]')).toBeDisabled();
  await page.locator('[name=trust_host]').check();
  await page.locator('[name=guest_password]').fill(account.guest_password);
  await page.getByRole('button',{name:'Enroll this VM',exact:true}).click();
  await page.locator('#accept-confirm').click();
  await page.waitForURL(`**/vps/${account.enroll_id}#sshx`);
  await expect(page.getByRole('button',{name:'Generate SSHX',exact:true})).toBeEnabled();
  await expect(page.getByRole('link',{name:'Repair management access'})).toBeVisible();
  expect(await page.content()).not.toContain(account.guest_password);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
});


// Reuse this test's real authenticated session: another login would exceed the
// deliberately unchanged 15-attempt IP quota across the complete browser suite.
async function verifyPollingRecovery(page, account) {
  let polls=0;
  await page.route('**/api/jobs/*',async route=>{
    polls++;
    if(polls===1)return route.abort('connectionfailed');
    return route.continue();
  });
  await page.goto(`/vps/${account.polling_id}#sshx`);
  await page.getByRole('button',{name:'Generate SSHX',exact:true}).click();
  await page.locator('#accept-confirm').click();
  await expect(page.locator('[data-sshx-state]')).toHaveText('Running',{timeout:15000});
  await expect(page.locator('[data-sshx-message]')).toContainText('verified SSH');
  const expected=`https://sshx.io/s/ui-protocol-${account.polling_id.replaceAll('-','')}#SyntheticUIKey0001`;
  await expect(page.locator('#sshx-link')).toHaveText(expected,{timeout:20000});
  expect(polls).toBeGreaterThanOrEqual(3);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  await page.getByRole('button',{name:'Stop SSHX',exact:true}).click();
  await page.locator('#accept-confirm').click();
  await expect(page.locator('#sshx-link')).toHaveCount(0,{timeout:20000});
}
