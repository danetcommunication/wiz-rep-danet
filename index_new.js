
const axios = require('axios');
var fs = require('fs');


const LOGFILE = "c:\\dmax\\log.txt"
const MAXLOGSIZE = 1000000;
const SCANEXT = ["exe","msi","pdf","txt","DOC","xls","jpg","bmp","ppt","xlsx","docx","pptx","zip","rar","7z","DTA","DAT","csv"];
const DMAXIP = "192.168.227.12"
const DMAXAPIKEY = "583fb8e93c6e4c16a7a4f7ada0599153"
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';


log = (str) => {
    fs.appendFileSync(LOGFILE,str + "\n")
}




const snooze = ms => new Promise(resolve => setTimeout(resolve, ms));

start = async (filepath,myfilename) => {
    log(filepath)
    let found = 0;
    SCANEXT.forEach((el) => {
        if (myfilename.includes(el)) {
            found = 1
            log("file needs to be scan " + myfilename )
        }
    })
    found = 1
    if (found == 1) {
        log("sending to sending to DMAX")
        let data = fs.readFileSync(filepath);

        let config = {
            method: 'post',
            maxBodyLength: Infinity,
            url: "https://"+ DMAXIP+"/avsanitizesync",
            headers: { 
                'filename': encodeURI(myfilename), 
                'apikey': DMAXAPIKEY, 
                'Content-Type': 'application/octet-stream'
            },
            data : data
        };
        try {
            let resp = await axios.request(config)
            log(resp.data)
	    if (resp.data.result == 0) { 
                printResult(0,"DMAX Pass")
            } else {
                printResult(1,"dmax Block")
            }	
        } catch (e) {
            log(e)
            printResult(0,"error when sending to DMAX")
        }
           
        
    } else {
        printResult(0,"Bypass DMAX")
    }
    process.exit(0);
}


printResult = (res,risk) => {
    const start = Date.now();
    let result = {
        "def_time":start,
        "scan_result_i": res,
        "threat_found": "Overall risk level is " + risk
    }
    console.log(JSON.stringify(result))
    log("------------finished file " +  process.argv[2] + "-----------------")
    
}


log("-------------starting process of file " +  process.argv[2] + " ----------------")



process.stdin.on('readable', () => {
    let chunk;
    try {
        const stats = fs.statSync(LOGFILE);
        const fileSizeInBytes = stats.size;
        if (fileSizeInBytes > MAXLOGSIZE) {
            fs.unlinkSync(LOGFILE);
        }
    } catch (e) {
        log(e);
    }
    // Use a loop to make sure we read all available data.
    while ((chunk = process.stdin.read()) !== null) {
      let paramsstr = (`${chunk}`);
      let jsonparam = JSON.parse(paramsstr)
      log("filename is " + jsonparam.file_info.display_name)
      start(process.argv[2],jsonparam.file_info.display_name)
    }
  });





