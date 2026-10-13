import Image from 'next/image';

/**
 * SecureOTA brand lockup.
 *
 * The mark is the shield-and-chip emblem from pics/logo-secureota.png,
 * trimmed and resized to 160x160 (public/brand/logo-secureota.png) so it is
 * sharp at 2x for the 32-40px sizes used here. The wordmark renders as
 * `secure` + `<em>ota</em>`; `.ota-brand` in app/design-system.css lowercases
 * it and paints the em in --ember, so the markup stays readable.
 *
 * `size` is the mark's rendered edge in px; width and height are always set
 * explicitly so the lockup reserves its space and cannot cause layout shift.
 */
export default function Logo({
  size = 32,
  wordmarkSize = 21,
  showWordmark = true,
  className = '',
  tone = 'auto',
}: {
  size?: number;
  wordmarkSize?: number;
  showWordmark?: boolean;
  className?: string;
  /** 'auto' follows the theme; 'light' forces white ink for dark panels. */
  tone?: 'auto' | 'light';
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
          data-tone={tone}
          style={{ fontSize: wordmarkSize, lineHeight: 1, color: tone === 'light' ? '#fff' : 'var(--logo-ink, #fff)' }}
        >
          secure<em>ota</em>
        </span>
      )}
    </span>
  );
}
