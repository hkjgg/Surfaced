import { ImageResponse } from "next/og";

/**
 * The home-screen icon: the same cursor block as app/icon.svg.
 *
 * Generated rather than committed as a PNG, so there is one definition of the
 * mark and no binary to regenerate by hand when it changes. It is drawn as a
 * filled element, not the "▮" character, so it does not depend on a font
 * shaping that glyph identically everywhere.
 */
export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          // Literal token values: --color-bg and --color-accent. An image
          // generated outside the document cannot read CSS variables.
          background: "#0a0b0d",
        }}
      >
        <div
          style={{
            width: 56,
            height: 100,
            borderRadius: 8,
            background: "#8e81f7",
          }}
        />
      </div>
    ),
    size,
  );
}
