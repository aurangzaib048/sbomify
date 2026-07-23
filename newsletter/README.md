# sbomify Newsletter Template

An [MJML](https://mjml.io/) template for the sbomify newsletter. MJML compiles to
responsive, email-client-safe HTML (including Outlook), so we only maintain the
high-level markup here.

The design matches the transactional email branding in
`sbomify/apps/core/templates/core/emails/base.html.j2`: dark navy header with the
white logo and "The Security Artifact Hub" tagline, brand blue (`#4059d0`)
buttons and links, and the brand gradient (blue → pink → peach) as an accent bar.

## Compiling

No install needed — run from the repo root:

```bash
bunx mjml newsletter/sbomify-newsletter.mjml -o newsletter/sbomify-newsletter.html
```

Preview while editing:

```bash
bunx mjml --watch newsletter/sbomify-newsletter.mjml -o /tmp/newsletter.html
```

You can also paste the template into the [MJML live editor](https://mjml.io/try-it-live)
for a quick visual preview.

Alternatively, run the **Build Newsletter** workflow from the GitHub Actions tab
(`.github/workflows/newsletter.yml`, manual trigger). It compiles the template
and uploads the HTML as a `newsletter-html` build artifact you can download
from the run page.

## Writing an issue

1. Copy `sbomify-newsletter.mjml` (or edit in place and don't commit the issue).
2. Replace every `[[PLACEHOLDER]]` — issue title, preview text, intro, featured
   story, product updates, and reading links. Drop sections that don't apply for
   a given issue (e.g. remove an update block or the "Worth reading" box).
3. Replace `[[UNSUBSCRIBE_URL]]`, `[[WEB_VERSION_URL]]`, and
   `[[SENDER_POSTAL_ADDRESS]]` with your email provider's merge tags — the
   unsubscribe link and postal address are legally required (CAN-SPAM/GDPR).
4. Compile and send the generated HTML through the provider.

## Notes

- The header logo is loaded from `https://app.sbomify.com/static/img/sbomify-white.svg`.
  Some clients (notably Gmail) don't render SVG images — if that matters for your
  audience, upload a white-on-transparent PNG to the ESP's CDN and swap the URL.
- Images should be hosted at 2× their display width for retina screens (the
  feature image slot displays at 520px inside a 600px layout, so upload ~1040px).
- Keep `mj-preview` text meaningful — it's the snippet shown next to the subject
  line in most inboxes.
