# How to bring your own [Twilio Verify](https://www.twilio.com/verify) API key



To bring your own Twilio Verify API key, you need to fill up the following during registration:
```
"twilioConfig": {
    "apiSID": "YOUR_SID",
    "apiSecret": "YOUR_SECRET",
    "serviceSID": "YOUR_SERVICE_SID"
}
```

Follow the steps below to get the values of `YOUR_SID`, `YOUR_SECRET`, and `YOUR_SERVICE_SID`:
1. [Sign up a Twilio account with free credits](https://www.twilio.com/try-twilio) if you don't have one. You might want to check [Twilio's Pricing](https://www.twilio.com/verify/pricing) if you are not familiar with it.
2. Sign in to [Twilio Console](https://console.twilio.com/). Click **Account** at the top right and select **API keys and tokens**. Click **Create API key**, set an arbtrary **Friendly name** for the key , and then click **Create API Key** to create your API key.
    - The **SID** and **Secret** showed on the screen are `YOUR_SID` and `YOUR_SECRET`.
3. Type **Verify** in the search box at the top and go to **Verify services**. Click **+** to create a new service by entering a **FRIENDLY NAME**, which has to be `Let's eSign`. (Note the `Let's eSign` naming is really mandatory.)
    - The **SERVICE SID** showed on the screen is `YOUR_SERVICE_SID`. 
