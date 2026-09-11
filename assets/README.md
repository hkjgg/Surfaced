# assets

One font file, copied here on purpose.

`next/og` renders the Open Graph and Apple touch icons with Satori, which needs
real font data — it has no default font. The obvious source is
`node_modules/geist/dist/fonts/…`, and that works while the images are
generated at build time. It stops working the moment a route carrying one is
traced as dynamic, because `node_modules` is not part of the serverless bundle
unless it is explicitly traced in.

Copying the one weight used removes that failure mode, and keeps image
generation offline — the same reason the project depends on the `geist` package
rather than `next/font/google`.

Source: `geist` npm package, `dist/fonts/geist-mono/GeistMono-Medium.ttf`.
Licence: SIL Open Font License 1.1, as shipped with that package.
