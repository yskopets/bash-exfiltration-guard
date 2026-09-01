// Probe: does tree-sitter-bash produce an error-free tree for each line?
//
// tree-sitter never throws: it recovers from anything by inserting ERROR
// nodes. hasError is therefore the only signal that the parse was wrong,
// and a caller that forgets to check it fails open.
const Parser = require('tree-sitter');
const Bash = require('tree-sitter-bash');
const fs = require('fs');

const p = new Parser();
p.setLanguage(Bash);

for (const line of fs.readFileSync(process.argv[2], 'utf8').trim().split('\n')) {
  const [name, cmd] = line.split('\t');
  const tree = p.parse(cmd);
  console.log(`${tree.rootNode.hasError ? 'ERROR' : 'OK   '} ${name}`);
}
