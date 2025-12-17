const { Builder, Browser, By } = require("selenium-webdriver");
const { Options } = require("selenium-webdriver/chrome");

exports.visit = async (req, res) => {
  if (!req.body?.dest)
    res.status(400).json({ message: "something missing in request body" });

  const dest = req.body.dest;
  try {
    new URL(dest);
  } catch {
    res.status(400).json({ message: "something missing in request body" });
  }

  let options = new Options();
  options.addArguments([
    "--headless=new",
    "--no-sandbox",
    "--disable-dev-shm-usage",
  ]);
  let driver = await new Builder()
    .forBrowser(Browser.CHROME)
    .setChromeOptions(options)
    .build();
  await driver.get(process.env.FLAG_DOMAIN);
  await driver.manage().addCookie({
    name: "flag",
    value: process.env.FLAG,
    sameSite: "Strict",
  });
  try {
    await driver.get(dest);
    res.status(200).json({
      message: "admin is visiting your web page, please wait a moment",
    });
    await driver.sleep(10 * 1000);
  } finally {
    await driver.quit();
  }
};
