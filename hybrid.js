const { padding } = require('aes-js')
const crypto=require('crypto')
const fs=require('fs')
var symmkey=crypto.randomBytes(32)
const algorithm = 'aes-256-ctr';
//using assymetric key pairs to share symmteric pairs

const {publicKey,privateKey}=crypto.generateKeyPairSync("rsa",{
    modulusLength:2048,
})


const readablestream=fs.createReadStream('home.txt','utf-8')
function encryptkey(symmkey)
{
    return crypto.publicEncrypt({
        key:fs.readFileSync('public_key.pem','utf-8'),
        padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash:'sha256'
    },
    Buffer.from(symmkey)
    )

}

function encrypttext(plainText)
{
    const iv =crypto.randomBytes(16)
    const cipher = crypto.createCipheriv(algorithm, symmkey, iv);
    const result=Buffer.concat([iv,cipher.update(plainText),cipher.final()])
    return result

}

readablestream.on('data',(chunk)=>{
    let encryptkeys=encryptkey(symmkey)
    console.log('encrypted key ',encryptkeys.toString('base64'))
    const decryptkeys=decryptkey(encryptkeys)
    console.log('decrypted key ',decryptkeys.toString())
    let encryptedtext=encrypttext(chunk)
    console.log('encrypted text ',encryptedtext.toString('base64'))
    let decryptedtext=decrypttext(encryptedtext)
    console.log('decrypted text:', decryptedtext.toString())


})




function decryptkey(encryptkeys)
{
    return crypto.privateDecrypt(
        {
            key:fs.readFileSync('private_key.pem','utf-8'),
            padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash:'sha256'
        },
        encryptkeys
    )
}
function decrypttext(encrypted)
{
    const iv=encrypted.slice(0,16)
    encrypted=encrypted.slice(16)
    const decipher=crypto.createDecipheriv(algorithm,symmkey,iv)
    const result=Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return result
}

//signing and verification
const signature = crypto.sign("sha256", Buffer.from('home.txt'), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
  
  console.log(signature.toString("base64"));
  const isVerified = crypto.verify(
    "sha256",
    Buffer.from('home.txt'),
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    signature
  );
  
  console.log("signature verified: ", isVerified);