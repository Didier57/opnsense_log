interface Props {
  code?: string | null;
  className?: string;
}

export function CountryFlag({ code, className }: Props) {
  if (!code || code.length !== 2) return null;
  const cc = code.toLowerCase();
  return (
    <img
      className={`flag-img${className ? ` ${className}` : ""}`}
      src={`https://flagcdn.com/16x12/${cc}.png`}
      srcSet={`https://flagcdn.com/32x24/${cc}.png 2x`}
      width={16}
      height={12}
      alt={code.toUpperCase()}
      title={code.toUpperCase()}
      loading="lazy"
      onError={(e) => {
        e.currentTarget.style.display = "none";
      }}
    />
  );
}
