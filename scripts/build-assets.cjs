/* Rebuild the committed, CDN-independent browser dependencies. */
const fs = require('fs');
const copies = [
 ['node_modules/lucide/dist/umd/lucide.min.js','static/vendor/lucide.min.js'],
 ['node_modules/chart.js/dist/chart.umd.js','static/vendor/chart.umd.js'],
 ['node_modules/@fontsource-variable/inter/files/inter-latin-wght-normal.woff2','static/fonts/inter-latin-variable.woff2'],
 ['node_modules/@xterm/xterm/lib/xterm.js','static/vendor/xterm.js'],
 ['node_modules/@xterm/xterm/css/xterm.css','static/vendor/xterm.css'],
 ['node_modules/@xterm/addon-fit/lib/addon-fit.js','static/vendor/xterm-addon-fit.js'],
 ['node_modules/@xterm/addon-web-links/lib/addon-web-links.js','static/vendor/xterm-addon-web-links.js'],
 ['node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2','static/fonts/jetbrains-mono-latin-variable.woff2'],
 ['node_modules/@xterm/xterm/LICENSE','static/vendor/LICENSE-xterm'],
 ['node_modules/@xterm/addon-fit/LICENSE','static/vendor/LICENSE-xterm-addon-fit'],
 ['node_modules/@xterm/addon-web-links/LICENSE','static/vendor/LICENSE-xterm-addon-web-links'],
 ['node_modules/@fontsource-variable/jetbrains-mono/LICENSE','static/fonts/LICENSE-jetbrains-mono'],
 ['node_modules/lucide/LICENSE','static/vendor/LICENSE-lucide'],
 ['node_modules/chart.js/LICENSE.md','static/vendor/LICENSE-chartjs.md'],
 ['node_modules/tailwindcss/LICENSE','static/vendor/LICENSE-tailwind'],
 ['node_modules/@fontsource-variable/inter/LICENSE','static/fonts/LICENSE-inter']
];
for(const [from,to] of copies) {fs.mkdirSync(require('path').dirname(to),{recursive:true}); fs.copyFileSync(from,to);}
