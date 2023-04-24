const fastify = require('fastify')({
  logger: true
})
const cors = require('@fastify/cors')
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require('@fastify/helmet')
 fastify.register(require('fastify-supabase'),{
  supabaseKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJldnFud29wcW5zbnllZGZmcmRyIiwicm9sZSI6ImFub24iLCJpYXQiOjE2ODIyMzU5NTMsImV4cCI6MTk5NzgxMTk1M30.zHC_d1zEVQmz58BfBsd5kVtN3gndxtxDcb98UFxNlss',
  supabaseUrl: 'https://bevqnwopqnsnyedffrdr.supabase.co',
  helmet
})

fastify.post('/register', async (request, reply) => {
  try {
    const {
      supabase
    } = fastify
    const {
      name,
      email,
      password
    } = request.body;
    const user = await supabase.from('users').select({
      email
    })
    if (user)
      return reply.status(400).json({
        msg: "The email already exists."
      });

    if (password.length < 6)
      return reply
        .status(400)
        .json({
          msg: "Password is at least 6 characters long."
        });

    // Password Encryption
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await supabase.from('users').insert({
      name,
      email,
      password: passwordHash
    })
    // Then create jsonwebtoken , refreshtoken to authentication
    const accesstoken = createAccessToken({
      id: newUser.email
    });
    const refreshtoken = createRefreshToken({
      id: newUser.email
    });

    reply.cookie("refreshtoken", refreshtoken, {
      httpOnly: true,
      path: "/user/refresh_token",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7d
    });

    reply.json({
      accesstoken
    });
  } catch (err) {
    return reply.status(500).json({
      msg: err.message
    });
  }

})

fastify.post('/login', async (request, reply) => {
  try {
    const {
      supabase
    } = fastify
    const {
      email,
      password
    } = request.body;
    const user = await supabase.from('users').select({
      email
    })
    if (!user)
      return reply.status(400).json({
        msg: "User does not exist."
      });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return reply.status(400).json({
      msg: "Incorrect password."
    });
    // Then create jsonwebtoken , refreshtoken to authentication
    const accesstoken = createAccessToken({
      id: newUser.email
    });
    const refreshtoken = createRefreshToken({
      id: newUser.email
    });

    reply.cookie("refreshtoken", refreshtoken, {
      httpOnly: true,
      path: "/user/refresh_token",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7d
    });

    reply.json({
      accesstoken
    });
  } catch (err) {
    return reply.status(500).json({
      msg: err.message
    });
  }
})

fastify.post('/logout', async (request, reply) => {
  try {
    reply.clearCookie("refreshtoken", {
      path: "/user/refresh_token"
    });
    return reply.json({
      msg: "Logged out"
    });
  } catch (err) {
    return reply.status(500).json({
      msg: err.message
    });
  }
})
const createAccessToken = (user) => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "11m"
  });
};
const createRefreshToken = (user) => {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d"
  });
};


fastify.listen({
  port: 3000
}, err => {
  if (err) throw err
  console.log(`server listening on ${fastify.server.address().port}`)
})