import { connect } from  'mongoose';
const dbConnect = async() =>{
  
  try{
      const mongoDbConnection = await connect(process.env.CONNECTION_STRING);
      console.log(`Database Connection : ${mongoDbConnection.connection.host}`)
  }catch(err){
    console.log(`Database connection failed  ${err}`)
    process.exit(1);
  }

}

export default dbConnect;