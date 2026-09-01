// Probe: can bash-parser (npm) parse each line of the shared corpus?
const parse = require('bash-parser');
const fs = require('fs');

for (const line of fs.readFileSync(process.argv[2], 'utf8').trim().split('\n')) {
  const [name, cmd] = line.split('\t');
  try {
    parse(cmd, { insertLOC: true });
    console.log(`OK    ${name}`);
  } catch (e) {
    console.log(`FAIL  ${name.padEnd(24)} ${String(e.message).split('\n')[0]}`);
  }
}
