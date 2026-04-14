const RU_TO_EN: Record<string, string> = {
  "й": "q", "ц": "w", "у": "e", "к": "r", "е": "t",
  "н": "y", "г": "u", "ш": "i", "щ": "o", "з": "p",
  "х": "[", "ъ": "]",
  "ф": "a", "ы": "s", "в": "d", "а": "f", "п": "g",
  "р": "h", "о": "j", "л": "k", "д": "l",
  "ж": ";", "э": "'",
  "я": "z", "ч": "x", "с": "c", "м": "v", "и": "b",
  "т": "n", "ь": "m", "б": ",", "ю": ".",
  "ё": "`",
};

const EN_TO_RU: Record<string, string> = {
  "q": "й", "w": "ц", "e": "у", "r": "к", "t": "е",
  "y": "н", "u": "г", "i": "ш", "o": "щ", "p": "з",
  "[": "х", "]": "ъ",
  "a": "ф", "s": "ы", "d": "в", "f": "а", "g": "п",
  "h": "р", "j": "о", "k": "л", "l": "д",
  ";": "ж", "'": "э",
  "z": "я", "x": "ч", "c": "с", "v": "м", "b": "и",
  "n": "т", "m": "ь", ",": "б", ".": "ю",
  "`": "ё",
};

export function ruToEn(input: string): string {
  return input
    .split("")
    .map((ch) => {
      const lower = ch.toLowerCase();
      const mapped = RU_TO_EN[lower];
      if (!mapped) return ch;
      return ch === lower ? mapped : mapped.toUpperCase();
    })
    .join("");
}

export function enToRu(input: string): string {
  return input
    .split("")
    .map((ch) => {
      const lower = ch.toLowerCase();
      const mapped = EN_TO_RU[lower];
      if (!mapped) return ch;
      return ch === lower ? mapped : mapped.toUpperCase();
    })
    .join("");
}

export function hasRussian(input: string): boolean {
  return /[а-яА-ЯёЁ]/.test(input);
}

export function resolveCommand(input: string): string {
  if (hasRussian(input)) {
    return ruToEn(input);
  }
  return input;
}
