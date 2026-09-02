import Image from 'next/image';

/**
 * SecureOTA brand lockup.
 *
 * The mark is the 3D ring sculpture supplied by the design project
 * (public/brand/logo-secureota.png, 500x500). The wordmark renders as
 * `secure` + `<em>ota</em>`; `.ota-brand` in app/design-system.css lowercases
 * it and paints the em in --ember, so the markup stays readable.
 *
 * NOTE: the source PNG is 179 KB at 500x500 and next.config.mjs sets
 * `images: { unoptimized: true }`, so nothing downsizes it for the 32px
 * render. Worth replacing with a small trimmed PNG or an SVG trace.
 *
 * `size` is the mark's rendered edge in px; width and height are always set
 * explicitly so the lockup reserves its space and cannot cause layout shift.
 */
export default function Logo({
  size = 32,
  wordmarkSize = 21,
  showWordmark = true,
  className = '',
}: {
  size?: number;
  wordmarkSize?: number;
  showWordmark?: boolean;
  className?: string;
}) {
  return (
    <span className={`inline-flex items-center gap-2.5 ${className}`}>
      <Image
        src="/brand/logo-secureota.png"
        alt={showWordmark ? '' : 'SecureOTA'}
        width={size}
        height={size}
        priority
        style={{ width: size, height: size, objectFit: 'contain', display: 'block' }}
      />
      {showWordmark && (
        <span
          translate="no"
          className="ota-brand"
          style={{ fontSize: wordmarkSize, lineHeight: 1, color: '#fff' }}
        >
          secure<em>ota</em>
        </span>
      )}
    </span>
  );
}
