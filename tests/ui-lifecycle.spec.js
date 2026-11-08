// Actual HTTP/forms/queue/authorization with an explicit test-only engine state
// machine on port 5559. This is NOT native VM/container lifecycle evidence.
const {test,expect}=require('@playwright/test');
const fs=require('fs');
const accounts=()=>JSON.parse(fs.readFileSync('test-results/.sshx-ui-credentials.json','utf8'));

async function login(page,account,other=false){
  await page.goto('/login');
  await page.locator('[name=email]').fill(other?account.other_email:account.email);
  await page.locator('[name=password]').fill(account.password);
  await page.getByRole('button',{name:'Sign in to workspace'}).click();
  await page.waitForURL('**/user');
}
const button=(page,id,kind)=>page.locator(`form[action="/vps/${id}/action/${kind}"] button[type=submit]`);
async function completed(page){
  await page.waitForURL('**/vps/jobs/*');
  await expect(page.locator('#job-state')).toHaveText('Completed',{timeout:20000});
  await expect(page.locator('#job-message')).not.toContainText('error');
}
async function backToInstance(page){
  await completed(page);
  await page.locator('#job-instance-link').click();
}
async function fits(page){
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
}

test('assigned owner starts, stops, restarts and deletes own VPS; controls update live and outsiders are denied',async({page,browser},info)=>{
  const account=accounts()[info.project.name],id=account.lifecycle_id,errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await login(page,account);await page.goto(`/vps/${id}`);
  await expect(button(page,id,'start')).toBeEnabled();
  await expect(button(page,id,'stop')).toBeDisabled();
  await expect(button(page,id,'restart')).toBeDisabled();
  await expect(button(page,id,'delete')).toBeEnabled();
  await fits(page);

  const context=await browser.newContext(),outsider=await context.newPage();
  await login(outsider,account,true);
  const outsiderToken=await outsider.locator('meta[name=csrf-token]').getAttribute('content');
  for(const kind of ['start','stop','restart','force_stop','delete']){
    const denied=await outsider.request.post(`/vps/${id}/action/${kind}`,{form:{csrf_token:outsiderToken}});
    expect(denied.status()).toBe(404);
  }
  await context.close();

  await button(page,id,'start').click();await backToInstance(page);
  await expect(button(page,id,'start')).toBeDisabled();
  await expect(button(page,id,'stop')).toBeEnabled();
  await expect(button(page,id,'restart')).toBeEnabled();
  await fits(page);

  await button(page,id,'stop').click();
  await expect(page.locator('#confirm-dialog')).toBeVisible();
  await page.locator('#cancel-confirm').click();
  await expect(page).toHaveURL(new RegExp(`/vps/${id}$`));
  expect((await (await page.request.get(`/api/vps/${id}/metrics`)).json()).status).toBe('running');
  await button(page,id,'stop').click();await page.locator('#accept-confirm').click();
  await backToInstance(page);
  await expect(button(page,id,'start')).toBeEnabled();
  await expect(button(page,id,'stop')).toBeDisabled();

  // A second tab changes state. The first tab must update button availability
  // from real API responses without a manual reload or optimistic success.
  const other=await page.context().newPage();await other.goto(`/vps/${id}`);
  await button(other,id,'start').click();await completed(other);
  await expect(button(page,id,'start')).toBeDisabled({timeout:15000});
  await expect(button(page,id,'stop')).toBeEnabled();
  await expect(button(page,id,'restart')).toBeEnabled();
  await other.close();

  await button(page,id,'restart').click();await page.locator('#accept-confirm').click();
  await backToInstance(page);
  await expect(button(page,id,'start')).toBeDisabled();
  await expect(button(page,id,'stop')).toBeEnabled();

  await page.goto('/vps');await fits(page);
  await button(page,id,'delete').click();
  await expect(page.locator('#confirm-message')).toContainText('stopped gracefully');
  await page.locator('#cancel-confirm').click();
  expect((await page.request.get(`/api/vps/${id}/metrics`)).status()).toBe(200);
  await button(page,id,'delete').click();await page.locator('#accept-confirm').click();
  await completed(page);
  await expect(page.locator('#job-instance-link')).toBeHidden();
  expect((await page.request.get(`/api/vps/${id}/metrics`)).status()).toBe(404);
  await page.getByRole('link',{name:'Back to My VPS'}).click();
  await expect(page.locator(`a[href="/vps/${id}"]`)).toHaveCount(0);
  await fits(page);
  expect(errors).toEqual([]);
});
