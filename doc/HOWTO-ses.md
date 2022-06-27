# How to bring your own [AWS SES](https://aws.amazon.com/ses/) credential

To bring your own AWS SES credential, you need to fill up the following during registration:
```
"sesConfig": {
    "sesSMTPUsername": "YOUR_SMTP_USERNAME",
    "sesSMTPPassword": "YOUR_SMTP_PASSWORD"
}
```

Follow the steps below to get the values of `YOUR_SMTP_USERNAME` and `YOUR_SMTP_PASSWORD` from AWS SES (which allows you to [send 62,000 messages per month at no charge](https://aws.amazon.com/ses/pricing/)):
1. Sign in to your AWS console, go to Amazon Simple Email Service (SES), and then change your AWS region to **N. Virginia** (aka **us-east-1**) at the top right. Note the region change is mandatory.
2. Expand the menu at the left-hand side, go to the **Verified Identities** panel, and then click **Create identity** at the right-hand side.
3. Next, select **Domain** in **Identity type**, enter your company email domain (e.g., `apple.com`), and then click **Create identity** at the bottom.
4. Follow the on-screen instructions to **Publish DNS records** for DNS validation. Once verified, you can see the  **Status** of your email domain becomes *Verified* in the **Verified Identities** panel.
5. Go to the **Account dashboard** of Amazon SES via the menu at the left-hand side, scroll down to **Simple Mail Transfer Protocol (SMTP) settings**, and then click **Create SMTP credentials**.
6.  Click **Create** and you will be presented with `YOUR_SMTP_USERNAME` and `YOUR_SMTP_PASSWORD`.

Note if you are a first-time user, your AWS SES account would be in the sandbox mode which only allows you to
- Send 200 emails per day
- Send emails to addresses of the verified domain

Check [how to move out of the Amazon SES sandbox](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html) to gain full access.
