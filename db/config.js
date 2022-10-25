const mongoose = require("mongoose");

const dbConnection = () => {

    try {

        mongoose.connect(process.env.DB_CNN, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });

        console.log('BD Online');

    } catch (error) {

        console.log(error);

        throw new Error('Error a la hora de inicializar la BD');

    };

};

module.exports = {
    dbConnection
}