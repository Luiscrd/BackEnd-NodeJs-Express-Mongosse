const { request, response } = require('express');
const Usuario = require('../models/Usuario');
const bcrypt = require('bcryptjs');
const { generarJWT } = require('../helpers/jwt');

const crearUsuario = async( req = request, res = response ) => {

    const { name, email, password } = req.body;

    try {
        
        // Verificar email no existente
        const usuario = await Usuario.findOne({ email });

        if ( usuario ) {

            return res.status(400).json({
                ok: false,
                msg: 'El email ya existe'
            });

        }

        // Crear usuario con el modelo
        const dbUser = new Usuario( req.body );

        // Hashear la contraseña
        const salt = bcrypt.genSaltSync(10);
        dbUser.password = bcrypt.hashSync( password, salt );

        // Generar el JWT
        const token = await generarJWT( dbUser.id, name );

        // Crear usuario de BD
        dbUser.save();

        // Generar Respuesta
        return res.status(201).json({
            ok: true,
            msg: 'Usuario creado correctamente',
            uid: dbUser.id,
            name,
            token
        });

    } catch (error) {

        console.log(error);
        
        return res.status(500).json({
            ok: false,
            msg: 'Pongase en contacto con el administrador'
        });

    }

}

const loginUsuario = async( req = request, res = response ) => {

    const { email, password } = req.body;

    try {

        const dbUser = await Usuario.findOne({ email });

        // Comprobar que el usuario existe
        if ( !dbUser ) {

            return res.status(400).json({
                ok: false,
                msg: 'Usuario o contraseña icorrecta'
            });
            
        }

        // Validar password
        const validPassword = bcrypt.compareSync( password, dbUser.password );

        if ( !validPassword ) {

            return res.status(400).json({
                ok: false,
                msg: 'Usuario o contraseña icorrecta'
            });
            
        }

         // Generar el JWT
         const token = await generarJWT( dbUser.id, dbUser.name );

        return res.status(200).json({
            ok: true,
            msg: 'Login correcto',
            uid: dbUser.id,
            name: dbUser.name,
            token

        });
        
    } catch (error) {

        console.log(error);

        return res.status(500).json({
            ok: false,
            msg: 'Pongase en contacto con el administrador'
        });
        
    }

}

const renewToken = async( req = request, res = response ) => {

    // Sacar id y name del req
    const { uid, name } = req;
    
    // Generar nuevo JWT
    const token = await generarJWT( uid, name );

    return res.status(200).json({
        ok: true,
        uid,
        name,
        token
    });

}

module.exports = {
    crearUsuario,
    loginUsuario,
    renewToken
}