import rollupNodeResolve from "rollup-plugin-node-resolve";

export default [
	{
        entry: "es6.js",
		dest: "bundle.js",
		format: "iife",
        outro: `
window.handleWhereIsCA = handleWhereIsCA;
window.handleFileCACert = handleFileCACert;
window.handleFileCAPrivateKey = handleFileCAPrivateKey;
window.createCACert = createCACert;
window.createCert = createCert;
window.copyToClipboard = copyToClipboard;
window.handleOriginCert = handleOriginCert;
window.handleUploadDerCert = handleUploadDerCert;
window.handleUploadDerPrivateKey = handleUploadDerPrivateKey;
window.handleUploadPKCS12Cert = handleUploadPKCS12Cert;
window.handleUploadJKS = handleUploadJKS;
function context(name, func) {}`,
        plugins: [
            rollupNodeResolve({ jsnext: true, main: true })
        ]
	},
];
