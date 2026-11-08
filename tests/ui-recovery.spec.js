// Explicit browser protocol/engine fixtures, not native VM compatibility proof.
const {test,expect}=require('@playwright/test');
const fs=require('fs');
const accounts=()=>JSON.parse(fs.readFileSync('test-results/.sshx-ui-credentials.json','utf8'));
const button=(page,id,kind)=>page.locator(`form[action="/vps/${id}/action/${kind}"] button[type=submit]`);

test('blocking job is visible; only an admin can inspect/close interrupted power work and owner controls recover live',async({page,browser},info)=>{
  const account=accounts()[info.project.name],id=account.blocked_id,job=account.blocked_job,errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/login');
  await page.locator('[name=email]').fill(account.email);await page.locator('[name=password]').fill(account.password);
  await page.getByRole('button',{name:'Sign in to workspace'}).click();await page.waitForURL('**/user');
  await page.goto(`/vps/${id}`);
  const blocker=page.locator(`[data-operation-blockers="${id}"]`);
  await expect(blocker).toBeVisible();await expect(blocker).toContainText(job.slice(0,8));
  await expect(button(page,id,'stop')).toBeDisabled();await expect(button(page,id,'restart')).toBeDisabled();
  await blocker.getByRole('link',{name:/Open job/}).click();
  await expect(page.locator('#job-state')).toHaveText('Uncertain');
  await expect(page.locator('[data-job-recovery]')).toHaveCount(0);
  const token=await page.locator('meta[name=csrf-token]').getAttribute('content');
  for(const action of ['cancel','reconcile','close-power']){
    expect((await page.request.post(`/admin/jobs/${job}/${action}`,{form:{csrf_token:token}})).status()).toBe(403);
  }
  await page.locator('#job-instance-link').click();
  const context=await browser.newContext(),admin=await context.newPage();
  admin.on('pageerror',error=>errors.push(error.message));
  await admin.goto('http://127.0.0.1:5559/login');
  await admin.locator('[name=email]').fill(account.admin_email);await admin.locator('[name=password]').fill(account.password);
  await admin.getByRole('button',{name:'Sign in to workspace'}).click();await admin.waitForURL('**/dashboard');
  await admin.goto(`http://127.0.0.1:5559/admin/recovery?instance=${id}`);
  const card=admin.locator(`[data-recovery-job="${job}"]`);
  await expect(card).toBeVisible();await expect(card.getByRole('button',{name:'Inspect actual outcome'})).toBeVisible();
  const close=card.getByRole('button',{name:'Close interrupted power request'});
  await close.click();await expect(admin.locator('#confirm-dialog')).toBeVisible();
  await admin.locator('#cancel-confirm').click();
  expect((await (await admin.request.get(`/api/jobs/${job}`)).json()).status).toBe('uncertain');
  expect(await admin.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  await admin.screenshot({path:`test-results/recovery-${info.project.name}.png`,fullPage:true});
  await close.click();await admin.locator('#accept-confirm').click();
  await admin.waitForURL(`**/vps/jobs/${job}`);
  await expect(admin.locator('#job-state')).toHaveText('Failed');
  await expect(admin.locator('#job-message')).toContainText('original outcome is not claimed');
  await expect(blocker).toBeHidden({timeout:15000});
  await expect(button(page,id,'stop')).toBeEnabled();await expect(button(page,id,'restart')).toBeEnabled();
  await expect(button(page,id,'delete')).toBeEnabled();
  expect((await (await page.request.get(`/api/vps/${id}/metrics`)).json()).status).toBe('running');
  await button(page,id,'stop').click();await page.locator('#accept-confirm').click();
  await page.waitForURL('**/vps/jobs/*');await expect(page.locator('#job-state')).toHaveText('Completed',{timeout:20000});
  await page.locator('#job-instance-link').click();await expect(button(page,id,'start')).toBeEnabled();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
  expect(errors).toEqual([]);await context.close();
});
