const {test,expect} = require('@playwright/test');
const crypto=require('crypto');

test('register, navigate, inspect real allocations and submit honest test-mode failure', async ({page}, testInfo)=>{
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('/');await expect(page.getByRole('heading',{name:'Your infrastructure. Without the overhead.'})).toBeVisible();
  await page.getByRole('link',{name:'Create your workspace'}).click();
  const password=crypto.randomBytes(18).toString('hex');
  await page.locator('[name=name]').fill('Browser Tester');
  await page.locator('[name=email]').fill(`ui-${crypto.randomUUID()}@example.test`);
  await page.locator('[name=password]').fill(password);await page.locator('[name=confirm_password]').fill(password);
  await page.getByRole('button',{name:'Create your workspace'}).click();await page.waitForURL('**/dashboard');
  await expect(page.locator('[data-total=count]')).toHaveText('0');
  await expect(page.locator('[data-total=ram_mb]')).toHaveText('0');
  await expect(page.getByText('No real VPS resources or success records will be created.')).toBeVisible();
  await page.waitForTimeout(5500);await expect(page.locator('#chart-awaiting')).toBeHidden();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  if(testInfo.project.name==='android'){
    await page.getByRole('button',{name:'Toggle navigation'}).click();await expect(page.locator('#sidebar')).toHaveClass(/open/);
    await page.locator('#sidebar').getByRole('link',{name:'My VPS',exact:true}).click();
  }else{await page.locator('#sidebar').getByRole('link',{name:'My VPS',exact:true}).click();}
  await expect(page.getByRole('heading',{name:'Your next environment starts here.'})).toBeVisible();
  await page.goto('/vps/create');await page.getByText('Docker container',{exact:true}).click();
  await expect(page.locator('.qemu-only')).toBeHidden();await expect(page.locator('.docker-only')).toBeVisible();
  await expect(page.locator('[name=public_key]')).toBeDisabled();
  await page.locator('[name=name]').fill('ui-not-a-real-vps');
  await page.locator('[name=allow_unenforced_storage]').check();
  await expect(page.locator('#summary-name')).toHaveText('ui-not-a-real-vps');
  await page.getByRole('button',{name:'Review configuration'}).click();
  await expect(page.locator('.toast-error')).toContainText('Test mode');
  const metrics=await page.request.get('/api/metrics');expect((await metrics.json()).totals.count).toBe(0);
  for(const path of ['/vps/console','/profile','/settings','/docs']){expect((await page.goto(path)).status()).toBe(200);}
  expect((await page.goto('/admin')).status()).toBe(403);
  expect(errors).toEqual([]);
});

test('unauthenticated routes and documentation work on both screen sizes',async({page})=>{
  await page.goto('/dashboard');await expect(page).toHaveURL(/\/login/);
  await page.goto('/docs');await expect(page.getByRole('heading',{name:'External Linux provisioning nodes'})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
});

const fs=require('fs');
const path=require('path');
const accounts=()=>JSON.parse(fs.readFileSync(process.env.SKVM_UI_CREDENTIALS||path.join(__dirname,'../test-results/.ui-credentials.json'),'utf8'));
async function signIn(page,account){
  await page.goto('/login');await page.locator('[name=email]').fill(account.email);await page.locator('[name=password]').fill(account.password);
  await page.getByRole('button',{name:'Sign in to workspace'}).click();await page.waitForURL('**/dashboard');
}

test('admin plans, quotas, node form, catalog, settings and guarded account deletion work in the browser',async({page,browser},testInfo)=>{
  const state=accounts(), managed=state.managed[testInfo.project.name], errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await signIn(page,state.admin);await page.goto('/admin');
  await expect(page.getByRole('heading',{name:'Admin control.'})).toBeVisible();
  const node=page.locator('form[action="/admin/nodes"]');await expect(node).toHaveCount(1);
  await node.locator('[name=name]').fill('Browser node '+testInfo.project.name);
  await node.locator('[name=url]').fill('https://unallowlisted.example.test');await node.locator('[name=token]').fill(crypto.randomBytes(24).toString('hex'));
  await node.getByRole('button',{name:'Connect & verify node'}).click();
  await expect(page.locator('.toast-error')).toContainText('allowlist');await expect(page).toHaveURL(/\/admin#nodes$/);
  const planName='Browser plan '+testInfo.project.name, plan=page.locator('#plans form.plan-edit-row').last();
  await plan.locator('[name=name]').fill(planName);
  for(const [key,value] of Object.entries({max_instances:2,ram_mb:1024,vcpus:1,disk_gb:16}))await plan.locator(`[name=${key}]`).fill(String(value));
  await plan.getByRole('button',{name:'Create',exact:true}).click();await expect(page.locator('.toast-success')).toBeVisible();
  let user=page.locator('form.user-edit-row').filter({hasText:managed.email});
  await user.locator('[name=plan_id]').selectOption({label:planName});await user.locator('[name=enabled]').uncheck();
  await user.getByRole('button',{name:'Save',exact:true}).click();await expect(page.locator('.toast-success')).toBeVisible();
  user=page.locator('form.user-edit-row').filter({hasText:managed.email});await expect(user.locator('[name=enabled]')).not.toBeChecked();
  const guestContext=await browser.newContext(), blocked=await guestContext.newPage();
  await blocked.goto('http://127.0.0.1:5558/login');await blocked.locator('[name=email]').fill(managed.email);await blocked.locator('[name=password]').fill(managed.password);
  await blocked.getByRole('button',{name:'Sign in to workspace'}).click();await expect(blocked.locator('.toast-error')).toContainText('Invalid email or password');
  await guestContext.close();
  await user.locator('[name=enabled]').check();await user.getByRole('button',{name:'Save',exact:true}).click();
  const image=page.locator('details.image-admin').filter({hasText:'Ubuntu 24.04'});await image.locator('summary').click();
  const imageForm=image.locator('form').first();await imageForm.locator('[name=sha256]').fill('a'.repeat(64));
  await imageForm.getByRole('button',{name:'Save configuration'}).click();await expect(page.locator('.toast-success')).toBeVisible();
  const settings=page.locator('#configuration form');await settings.locator('[name=max_instances_per_user]').fill('4');
  await settings.getByRole('button',{name:/Save/}).click();await expect(page.locator('.toast-success')).toBeVisible();
  await expect(page.locator('#configuration [name=max_instances_per_user]')).toHaveValue('4');
  const remove=page.locator('form.user-delete-row').filter({has:page.locator(`input[name=confirmation][value="${managed.email}"]`)});
  await remove.getByRole('button',{name:'Delete account'}).click();await expect(page.locator('#confirm-dialog')).toBeVisible();
  await page.locator('#cancel-confirm').click();await expect(remove).toBeVisible();
  await remove.getByRole('button',{name:'Delete account'}).click();await page.locator('#accept-confirm').click();
  await expect(page.locator('.toast-success')).toBeVisible();await expect(page.locator('form.user-edit-row').filter({hasText:managed.email})).toHaveCount(0);
  expect((await page.request.get('/api/metrics')).ok()).toBeTruthy();expect(errors).toEqual([]);
});

test('profile, password replacement, session revocation and logout are connected',async({page,browser},testInfo)=>{
  const account=accounts().profile[testInfo.project.name];await signIn(page,account);
  const otherContext=await browser.newContext(),other=await otherContext.newPage();
  await other.goto('http://127.0.0.1:5558/login');await other.locator('[name=email]').fill(account.email);await other.locator('[name=password]').fill(account.password);
  await other.getByRole('button',{name:'Sign in to workspace'}).click();await other.waitForURL('**/dashboard');
  await page.goto('/profile');const form=page.locator('form').filter({has:page.locator('[name=current_password]')});
  const replacement=crypto.randomBytes(18).toString('hex');
  await form.locator('[name=name]').fill('Updated Browser Profile');await form.locator('[name=current_password]').fill(account.password);
  await form.locator('[name=new_password]').fill(replacement);await form.getByRole('button',{name:/Save/}).click();
  await expect(page.locator('.toast-success')).toBeVisible();await expect(page.locator('[name=name]')).toHaveValue('Updated Browser Profile');
  expect((await other.request.get('http://127.0.0.1:5558/api/metrics')).status()).toBe(401);
  const revoke=page.locator('form[action="/sessions/revoke"]');await revoke.locator('[name=password]').fill(replacement);
  await revoke.getByRole('button',{name:/Revoke/}).click();await page.locator('#accept-confirm').click();await expect(page.locator('.toast-success')).toBeVisible();
  if(testInfo.project.name==='android')await page.getByRole('button',{name:'Toggle navigation'}).click();
  await page.locator('form[action="/logout"]').getByRole('button').click();await page.waitForURL('http://127.0.0.1:5558/');
  expect((await page.request.get('/api/metrics')).status()).toBe(401);await otherContext.close();
});

test('initial administrator login requires password rotation before APIs and controls',async({page,browser},testInfo)=>{
  const account=accounts().bootstrap[testInfo.project.name],errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/login');await page.locator('[name=email]').fill(account.email);await page.locator('[name=password]').fill(account.password);
  await page.getByRole('button',{name:'Sign in to workspace'}).click();await page.waitForURL('**/profile');
  await expect(page.getByRole('alert').filter({hasText:'Replace the public initial password'})).toBeVisible();
  await expect(page.locator('[name=new_password]')).toHaveAttribute('required','');
  await expect(page.locator('form[action="/sessions/revoke"]')).toHaveCount(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  const denied=await page.request.get('/api/metrics');expect(denied.status()).toBe(403);
  expect((await denied.json()).code).toBe('password_change_required');
  await page.goto('/admin');await expect(page).toHaveURL(/\/profile$/);
  const otherContext=await browser.newContext(),other=await otherContext.newPage();
  await other.goto('http://127.0.0.1:5558/login');await other.locator('[name=email]').fill(account.email);await other.locator('[name=password]').fill(account.password);
  await other.getByRole('button',{name:'Sign in to workspace'}).click();await other.waitForURL('**/profile');
  const form=page.locator('form').filter({has:page.locator('[name=current_password]')}),replacement=crypto.randomBytes(18).toString('hex');
  await form.locator('[name=current_password]').fill(account.password);await form.locator('[name=new_password]').fill(replacement);
  await form.getByRole('button',{name:/Save/}).click();await expect(page.locator('.toast-success')).toBeVisible();
  await expect(page.getByRole('alert').filter({hasText:'Replace the public initial password'})).toHaveCount(0);
  expect((await other.request.get('http://127.0.0.1:5558/api/metrics')).status()).toBe(401);
  await page.goto('/admin');await expect(page.getByRole('heading',{name:'Admin control.'})).toBeVisible();
  expect((await page.request.get('/api/metrics')).status()).toBe(200);expect(errors).toEqual([]);await otherContext.close();
});
