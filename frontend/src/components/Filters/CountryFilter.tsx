import { flagEmoji } from "../../format";

interface Props {
  value: string[];
  options: string[];
  onChange: (value: string[]) => void;
}

export function CountryFilter({ value, options, onChange }: Props) {
  if (options.length === 0) return null;

  const toggle = (code: string) => {
    onChange(value.includes(code) ? value.filter((c) => c !== code) : [...value, code]);
  };

  return (
    <div className="panel">
      <div className="filters">
        <strong>Pays</strong>
        {value.length > 0 && <button onClick={() => onChange([])}>Tous</button>}
        {options.map((code) => (
          <button
            key={code}
            className={`chip${value.includes(code) ? " active" : ""}`}
            onClick={() => toggle(code)}
            title={code}
          >
            {flagEmoji(code)} {code}
          </button>
        ))}
      </div>
    </div>
  );
}
