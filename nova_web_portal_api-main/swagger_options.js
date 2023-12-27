//API documentation
const swaggerOptions = {
  swaggerDefinition: {
    openapi: "3.0.1",
    info: {
      title: "Exposed API details",
      version: "1.0.0",
    },
    servers: [
      {
        url: "http://localhost:9000",
      },
    ],
    components: {
      securitySchemes: {
        BasicAuth: {
          type: "http",
          scheme: "basic"
        },
      },
    },
    security: [
      {
        BasicAuth: [],
      },
    ],
  },
  apis: ["./exposed_routes/*.js"],
};

module.exports = swaggerOptions