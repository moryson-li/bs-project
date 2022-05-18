const express = require('express')
const bodyParser = require('body-parser')
const app = express()
app.use(bodyParser.json())

const options = {
  mode: 'text',
  pythonPath: '/usr/bin/python3',
  pythonOptions: ['-u'],
  scriptPath: '/home/moryson/Desktop/project',
  args: []
};


//Disable CORS
app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});


app.get('/api', function(req, res) {
  console.log("start")

  const {PythonShell} = require('python-shell')
  //v = new PythonShell('main.py',options);

  const pyshell = PythonShell.run('main.py', options, function (err) {
    if (err) throw err;
    console.log('finished');
  });
  console.log("req")
  console.log(req.query.data) //Display data from the frontend in console.log
  res.send('aaa')

  pyshell.on('message',  function (data) {
    console.log(data)
    // res.send({   message: data  }) // Return the result of the operation to the frontend
  })

})

console.log("Start API Server for IT")
app.listen(3000)
