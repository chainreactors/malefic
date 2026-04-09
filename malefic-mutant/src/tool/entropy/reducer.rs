/// Entropy reduction strategies for PE files.
///
/// Three strategies to reduce Shannon entropy of binary data:
/// - NullBytes: append blocks of 0x00
/// - Pokemon: append Pokemon name strings (high frequency ASCII)
/// - RandomWords: append random lowercase ASCII words
use rand::Rng;

/// Strategy for reducing entropy.
#[derive(Debug, Clone, Copy)]
pub enum ReduceStrategy {
    NullBytes,
    Pokemon,
    RandomWords,
}

impl std::str::FromStr for ReduceStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "null" | "null_bytes" | "nullbytes" => Ok(ReduceStrategy::NullBytes),
            "pokemon" => Ok(ReduceStrategy::Pokemon),
            "random" | "random_words" | "randomwords" => Ok(ReduceStrategy::RandomWords),
            _ => Err(format!(
                "'{}' is not a valid strategy. Use: null_bytes, pokemon, random_words",
                s
            )),
        }
    }
}

impl std::fmt::Display for ReduceStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReduceStrategy::NullBytes => write!(f, "null_bytes"),
            ReduceStrategy::Pokemon => write!(f, "pokemon"),
            ReduceStrategy::RandomWords => write!(f, "random_words"),
        }
    }
}

/// 251 original Pokemon names — high-frequency ASCII text with low entropy.
const POKEMON_NAMES: &[&str] = &[
    "Bulbasaur",
    "Ivysaur",
    "Venusaur",
    "Charmander",
    "Charmeleon",
    "Charizard",
    "Squirtle",
    "Wartortle",
    "Blastoise",
    "Caterpie",
    "Metapod",
    "Butterfree",
    "Weedle",
    "Kakuna",
    "Beedrill",
    "Pidgey",
    "Pidgeotto",
    "Pidgeot",
    "Rattata",
    "Raticate",
    "Spearow",
    "Fearow",
    "Ekans",
    "Arbok",
    "Pikachu",
    "Raichu",
    "Sandshrew",
    "Sandslash",
    "NidoranF",
    "Nidorina",
    "Nidoqueen",
    "NidoranM",
    "Nidorino",
    "Nidoking",
    "Clefairy",
    "Clefable",
    "Vulpix",
    "Ninetales",
    "Jigglypuff",
    "Wigglytuff",
    "Zubat",
    "Golbat",
    "Oddish",
    "Gloom",
    "Vileplume",
    "Paras",
    "Parasect",
    "Venonat",
    "Venomoth",
    "Diglett",
    "Dugtrio",
    "Meowth",
    "Persian",
    "Psyduck",
    "Golduck",
    "Mankey",
    "Primeape",
    "Growlithe",
    "Arcanine",
    "Poliwag",
    "Poliwhirl",
    "Poliwrath",
    "Abra",
    "Kadabra",
    "Alakazam",
    "Machop",
    "Machoke",
    "Machamp",
    "Bellsprout",
    "Weepinbell",
    "Victreebel",
    "Tentacool",
    "Tentacruel",
    "Geodude",
    "Graveler",
    "Golem",
    "Ponyta",
    "Rapidash",
    "Slowpoke",
    "Slowbro",
    "Magnemite",
    "Magneton",
    "Farfetchd",
    "Doduo",
    "Dodrio",
    "Seel",
    "Dewgong",
    "Grimer",
    "Muk",
    "Shellder",
    "Cloyster",
    "Gastly",
    "Haunter",
    "Gengar",
    "Onix",
    "Drowzee",
    "Hypno",
    "Krabby",
    "Kingler",
    "Voltorb",
    "Electrode",
    "Exeggcute",
    "Exeggutor",
    "Cubone",
    "Marowak",
    "Hitmonlee",
    "Hitmonchan",
    "Lickitung",
    "Koffing",
    "Weezing",
    "Rhyhorn",
    "Rhydon",
    "Chansey",
    "Tangela",
    "Kangaskhan",
    "Horsea",
    "Seadra",
    "Goldeen",
    "Seaking",
    "Staryu",
    "Starmie",
    "MrMime",
    "Scyther",
    "Jynx",
    "Electabuzz",
    "Magmar",
    "Pinsir",
    "Tauros",
    "Magikarp",
    "Gyarados",
    "Lapras",
    "Ditto",
    "Eevee",
    "Vaporeon",
    "Jolteon",
    "Flareon",
    "Porygon",
    "Omanyte",
    "Omastar",
    "Kabuto",
    "Kabutops",
    "Aerodactyl",
    "Snorlax",
    "Articuno",
    "Zapdos",
    "Moltres",
    "Dratini",
    "Dragonair",
    "Dragonite",
    "Mewtwo",
    "Mew",
    "Chikorita",
    "Bayleef",
    "Meganium",
    "Cyndaquil",
    "Quilava",
    "Typhlosion",
    "Totodile",
    "Croconaw",
    "Feraligatr",
    "Sentret",
    "Furret",
    "Hoothoot",
    "Noctowl",
    "Ledyba",
    "Ledian",
    "Spinarak",
    "Ariados",
    "Crobat",
    "Chinchou",
    "Lanturn",
    "Pichu",
    "Cleffa",
    "Igglybuff",
    "Togepi",
    "Togetic",
    "Natu",
    "Xatu",
    "Mareep",
    "Flaaffy",
    "Ampharos",
    "Bellossom",
    "Marill",
    "Azumarill",
    "Sudowoodo",
    "Politoed",
    "Hoppip",
    "Skiploom",
    "Jumpluff",
    "Aipom",
    "Sunkern",
    "Sunflora",
    "Yanma",
    "Wooper",
    "Quagsire",
    "Espeon",
    "Umbreon",
    "Murkrow",
    "Slowking",
    "Misdreavus",
    "Unown",
    "Wobbuffet",
    "Girafarig",
    "Pineco",
    "Forretress",
    "Dunsparce",
    "Gligar",
    "Steelix",
    "Snubbull",
    "Granbull",
    "Qwilfish",
    "Scizor",
    "Shuckle",
    "Heracross",
    "Sneasel",
    "Teddiursa",
    "Ursaring",
    "Slugma",
    "Magcargo",
    "Swinub",
    "Piloswine",
    "Corsola",
    "Remoraid",
    "Octillery",
    "Delibird",
    "Mantine",
    "Skarmory",
    "Houndour",
    "Houndoom",
    "Kingdra",
    "Phanpy",
    "Donphan",
    "Porygon2",
    "Stantler",
    "Smeargle",
    "Tyrogue",
    "Hitmontop",
    "Smoochum",
    "Elekid",
    "Magby",
    "Miltank",
    "Blissey",
    "Raikou",
    "Entei",
    "Suicune",
    "Larvitar",
    "Pupitar",
    "Tyranitar",
    "Lugia",
    "HoOh",
    "Celebi",
];

/// Compute Shannon entropy from a frequency table and total count.
fn entropy_from_freq(freq: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
    let mut entropy = 0.0;
    for &count in freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Reduce entropy of data by appending low-entropy padding.
/// Returns the modified data and the final entropy value.
pub fn reduce_entropy(
    data: &[u8],
    threshold: f64,
    strategy: ReduceStrategy,
    max_growth: f64,
) -> (Vec<u8>, f64) {
    let original_len = data.len();
    let max_size = (original_len as f64 * max_growth) as usize;
    let mut result = data.to_vec();

    let mut freq = [0u64; 256];
    for &b in &result {
        freq[b as usize] += 1;
    }
    let mut total = result.len() as u64;
    let mut current_entropy = entropy_from_freq(&freq, total);

    if current_entropy <= threshold {
        return (result, current_entropy);
    }

    let mut rng = rand::thread_rng();
    let check_interval = 4096;
    let mut bytes_since_check: usize = 0;

    while current_entropy > threshold && result.len() < max_size {
        let chunk_start = result.len();

        match strategy {
            ReduceStrategy::NullBytes => {
                result.extend_from_slice(&[0u8; 4096]);
            }
            ReduceStrategy::Pokemon => {
                for _ in 0..64 {
                    let idx = rng.gen_range(0..POKEMON_NAMES.len());
                    result.extend_from_slice(POKEMON_NAMES[idx].as_bytes());
                    result.push(b' ');
                }
            }
            ReduceStrategy::RandomWords => {
                for _ in 0..64 {
                    let word_len = rng.gen_range(3..=10);
                    for _ in 0..word_len {
                        result.push(rng.gen_range(b'a'..=b'z'));
                    }
                    result.push(b' ');
                }
            }
        }

        for &b in &result[chunk_start..] {
            freq[b as usize] += 1;
        }
        total = result.len() as u64;
        bytes_since_check += result.len() - chunk_start;

        if bytes_since_check >= check_interval {
            current_entropy = entropy_from_freq(&freq, total);
            bytes_since_check = 0;
        }
    }

    current_entropy = entropy_from_freq(&freq, total);
    (result, current_entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduce_strategy_parse() {
        assert!(matches!(
            "null_bytes".parse::<ReduceStrategy>().unwrap(),
            ReduceStrategy::NullBytes
        ));
        assert!(matches!(
            "pokemon".parse::<ReduceStrategy>().unwrap(),
            ReduceStrategy::Pokemon
        ));
        assert!(matches!(
            "random_words".parse::<ReduceStrategy>().unwrap(),
            ReduceStrategy::RandomWords
        ));
        assert!("invalid".parse::<ReduceStrategy>().is_err());
    }

    #[test]
    fn test_reduce_null_bytes() {
        // Create somewhat random data
        let mut data = Vec::with_capacity(1024);
        let mut rng = rand::thread_rng();
        for _ in 0..1024 {
            data.push(rng.gen::<u8>());
        }

        let (result, entropy) = reduce_entropy(&data, 6.0, ReduceStrategy::NullBytes, 10.0);
        assert!(entropy <= 6.0);
        assert!(result.len() > data.len());
    }

    #[test]
    fn test_reduce_already_low() {
        let data = vec![0u8; 1024];
        let (result, entropy) = reduce_entropy(&data, 6.0, ReduceStrategy::NullBytes, 10.0);
        assert_eq!(result.len(), data.len());
        assert!(entropy <= 6.0);
    }
}
