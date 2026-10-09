interface Props {
  code?: string | null;
  className?: string;
}

function countryName(code: string): string {
  try {
    return new Intl.DisplayNames(["fr"], { type: "region" }).of(code) ?? code;
  } catch {
    return code;
  }
}

export function CountryFlag({ code, className }: Props) {
  if (!code || code.length !== 2) return null;
  const cc = code.toLowerCase();
  const label = countryName(code.toUpperCase());
  return (
    <img
      className={`flag-img${className ? ` ${className}` : ""}`}
      src={`https://flagcdn.com/16x12/${cc}.png`}
      srcSet={`https://flagcdn.com/32x24/${cc}.png 2x`}
      width={16}
      height={12}
      alt={label}
      title={label}
      loading="lazy"
      onError={(e) => {
        e.currentTarget.style.display = "none";
      }}
    />
  );
}
