package com.app.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
public class SpringSecurityConfig {

	@Autowired
	private JwtAuthenticationFilter authenticationFilter;;

	@Bean
	public SecurityWebFilterChain configure(ServerHttpSecurity http) {
		return http.authorizeExchange().pathMatchers("/api/autenticacion/oauth/token").permitAll()
				.pathMatchers(HttpMethod.POST, "/api/registro/registro/crear", "/api/registro/registro/crearNuevo",
						"/api/registro/registro/confirmarSuscripcion/**", "/api/usuarios/users/crearUsuarios")
				.permitAll()

				// Autenticacion
				.pathMatchers(HttpMethod.POST, "/api/autenticacion/autenticacion/arreglar").hasAnyRole("ADMIN")

				// Usuarios
				.pathMatchers(HttpMethod.GET, "/api/usuarios/users/listar", "/api/usuarios/roles/lista",
						"/api/usuarios/users/verUsuario/**", "/api/usuarios/users/encontrarUsuario/**",
						"/api/usuarios/users/file/downloadImage/**", "/api/usuarios/users/verRoleUsuario/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.pathMatchers(HttpMethod.GET, "/api/usuarios/users/editarPerfil/**",
						"/api/usuarios/users/verificarCodigo/**")
				.hasAnyRole("ADMIN", "USER").pathMatchers(HttpMethod.GET, "/api/usuarios/users/cedula")
				.hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.POST, "/api/usuarios/users/crear", "/api/usuarios/users/crearUsuariosRegistro")
				.hasAnyRole("ADMIN", "USER")
				.pathMatchers(HttpMethod.PUT, "/api/usuarios/users/eliminarAdmin/**",
						"/api/usuarios/users/editarUbicacion/**", "/api/usuarios/users/editar/**",
						"/api/usuarios/users/file/uploadImage/**")
				.hasAnyRole("ADMIN", "USER")
				.pathMatchers(HttpMethod.PUT, "/api/usuarios/users/roleModerator/**",
						"/api/usuarios/users/arreglarUsuario")
				.hasAnyRole("ADMIN").pathMatchers(HttpMethod.DELETE, "/api/usuarios/users/eliminar/**")
				.hasAnyRole("INTERVENTOR")

				// Busqueda
				.pathMatchers(HttpMethod.GET, "/api/busqueda/busqueda/buscar")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.pathMatchers(HttpMethod.POST, "/api/busqueda/busqueda/crear", "/api/busqueda/busqueda/arreglar").hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/busqueda/busqueda/editarProyecto",
						"/api/busqueda/busqueda/editarMuro", "/api/busqueda/busqueda/actualizarDatos")
				.hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/busqueda/busqueda/eliminarProyecto",
						"/api/busqueda/busqueda/eliminarMuro")
				.hasAnyRole("INTERVENTOR")

				// Estadistica
				.pathMatchers(HttpMethod.GET, "/api/estadistica/estadistica/verEstadistica/**",
						"/api/estadistica/estadistica/verLikes/**", "/api/estadistica/estadistica/verDislikes/**",
						"/api/estadistica/estadistica/verVisualizacion/**",
						"/api/estadistica/estadistica/verEstadisticasUsuario/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.pathMatchers(HttpMethod.GET, "/api/estadistica/estadistica/export/excel/**")
				.hasAnyRole("ADMIN", "MODERATOR", "INTERVENTOR")
				.pathMatchers(HttpMethod.POST, "/api/estadistica/estadistica/crearEna",
						"/api/estadistica/estadistica/arreglar")
				.hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/estadistica/estadistica/visualizaciones/**",
						"/api/estadistica/estadistica/obtenerEstadistica/**")
				.hasAnyRole("ADMIN", "USER")
				.pathMatchers(HttpMethod.DELETE, "/api/estadistica/estadistica/borrarEstadisticas/**",
						"/api/estadistica/estadistica/borrarEstadisticasUsuario/**")
				.hasAnyRole("INTERVENTOR")

				// Muro
				.pathMatchers(HttpMethod.GET, "/api/muro/muros/listar", "/api/muro/muros/buscar/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.pathMatchers(HttpMethod.POST, "/api/muro/muros/crear", "/api/muro/muros/crearProyectos")
				.hasAnyRole("ADMIN").pathMatchers(HttpMethod.PUT, "/api/muro/muros/eliminarProyecto/**")
				.hasAnyRole("INTERVENTOR").pathMatchers(HttpMethod.DELETE, "/api/muro/muros/eliminarMuro/**")
				.hasAnyRole("INTERVENTOR")

				// Notificaciones
				.pathMatchers(HttpMethod.GET, "/api/notificaciones/notificaciones/verNotificaciones/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.pathMatchers(HttpMethod.GET, "/api/notificaciones/notificaciones/editarUsuario/**",
						"/api/notificaciones/notificaciones/verificarCodigoUsuario/**",
						"/api/notificaciones/notificaciones/revisarNotificacion/**")
				.hasAnyRole("ADMIN", "INTERVENTOR")
				.pathMatchers(HttpMethod.POST, "/api/notificaciones/notificaciones/enviar")
				.hasAnyRole("ADMIN", "MODERATOR")
				.pathMatchers(HttpMethod.POST, "/api/notificaciones/notificaciones/crear",
						"/api/notificaciones/notificaciones/editEnabled",
						"/api/notificaciones/notificaciones/editEstado", "/api/notificaciones/notificaciones/registro",
						"/api/notificaciones/notificaciones/suscripciones",
						"/api/notificaciones/notificaciones/inscripciones")
				.hasAnyRole("ADMIN").pathMatchers(HttpMethod.PUT, "/api/notificaciones/enviarMensajeModerator/**")
				.hasAnyRole("ADMIN", "MODERATOR")
				.pathMatchers(HttpMethod.PUT, "/api/notificaciones/notificaciones/borrarNotificacion/**")
				.hasAnyRole("ADMIN", "USER")
				.pathMatchers(HttpMethod.PUT, "/api/notificaciones/notificaciones/cambiarNotificacion/**",
						"/api/notificaciones/notificaciones/arreglarNotificaciones")
				.hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/notificaciones/notificaciones/eliminarCodigoUsuario/**")
				.hasAnyRole("INTERVENTOR")
				.pathMatchers(HttpMethod.DELETE, "/api/notificaciones/notificaciones/eliminar")
				.hasAnyRole("INTERVENTOR")

				// PreguntasRespuestas
				.pathMatchers(HttpMethod.GET, "/api/preguntasrespuestas/preguntasrespuestas/obtenerProyectoByNombre/**",
						"/api/preguntasrespuestas/preguntasrespuestas/verPreguntas/**",
						"/api/preguntasrespuestas/preguntasrespuestas/verRespuestas/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.pathMatchers(HttpMethod.POST, "/api/preguntasrespuestas/preguntasrespuestas/crear").hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/preguntasrespuestas/preguntasrespuestas/respuestas/**",
						"/api/preguntasrespuestas/preguntasrespuestas/abrirCuestionario/**",
						"/api/preguntasrespuestas/preguntasrespuestas/respuestasPregunta/**",
						"/api/preguntasrespuestas/preguntasrespuestas/respuestaFinal/**")
				.hasAnyRole("ADMIN", "USER")
				.pathMatchers(HttpMethod.PUT, "/api/preguntasrespuestas/preguntasrespuestas/crearpreguntas/**")
				.hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.DELETE, "/api/preguntasrespuestas/preguntasrespuestas/borrarPreguntas/**")
				.hasAnyRole("INTERVENTOR")

				// Proyectos
				.pathMatchers(HttpMethod.GET, "/api/proyectos/proyectos/listar",
						"/api/proyectos/proyectos/descripcion/**", "/api/proyectos/proyectos/listarByMuro/**",
						"/api/proyectos/proyectos/obtenerProyectoByNombre/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.pathMatchers(HttpMethod.GET, "/api/proyectos/proyectos/verCreador/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "MODERATOR")
				.pathMatchers(HttpMethod.GET, "/api/proyectos/proyectos").hasAnyRole("ADMIN", "INTERVENTOR")
				.pathMatchers(HttpMethod.POST, "/api/proyectos/proyectos/crear").hasAnyRole("ADMIN", "MODERATOR")
				.pathMatchers(HttpMethod.PUT, "/api/proyectos/proyectos/visualizaciones/**").hasAnyRole("USER", "ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/proyectos/proyectos/eliminarAdmin/**",
						"/api/proyectos/proyectos/editEnabled/**", "/api/proyectos/proyectos/editarProyectos/**")
				.hasAnyRole("MODERATOR", "ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/proyectos/proyectos/arreglarCreador").hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.DELETE, "/api/proyectos/proyectos/eliminar/**").hasAnyRole("INTERVENTOR")

				// Recomendaciones
				.pathMatchers(HttpMethod.GET, "/api/recomendacion/recomendaciones/ubicacionMuro/**",
						"/api/recomendacion/recomendaciones/ubicacionProyectos/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.pathMatchers(HttpMethod.POST, "/api/recomendacion/recomendaciones/crear").hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/recomendacion/recomendaciones/editarUbicacion/**",
						"/api/recomendacion/recomendaciones/editarBusqueda/**")
				.hasAnyRole("ADMIN").pathMatchers(HttpMethod.DELETE, "/api/recomendacion/recomendaciones/eliminar/**")
				.hasAnyRole("INTERVENTOR")

				// Registro
				.pathMatchers(HttpMethod.GET, "/api/registro/registro/ver/**", "/api/registro/registro/contraseña")
				.hasAnyRole("ADMIN", "INTERVENTOR")

				// Suscripciones
				.pathMatchers(HttpMethod.GET, "/api/subscripciones/subscripciones/verificarInscripcion/**",
						"/api/suscripcionesretos/subscripciones/verComentarios/**",
						"/api/subscripciones/subscripciones/verificarCuestionario/**",
						"/api/subscripciones/subscripciones/revisarLikes/**")
				.hasAnyRole("ADMIN", "INTERVENTOR", "USER")
				.pathMatchers(HttpMethod.GET, "/api/subscripciones/subscripciones/obtenerProyectoByNombre/**")
				.hasAnyRole("ADMIN", "INTERVENTOR")
				.pathMatchers(HttpMethod.POST, "/api/subscripciones/subscripciones/crear").hasAnyRole("ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/subscripciones/subscripciones/inscripciones/**",
						"/api/subscripciones/subscripciones/anularInscripciones/**",
						"/api/subscripciones/subscripciones/comentarios/**",
						"/api/subscripciones/subscripciones/inscribirCuestionario/**",
						"/api/subscripciones/subscripciones/likes/**")
				.hasAnyRole("USER", "ADMIN")
				.pathMatchers(HttpMethod.PUT, "/api/subscripciones/suscripciones/arreglarSuscripciones")
				.hasAnyRole("ADMIN").pathMatchers(HttpMethod.DELETE, "/api/subscripciones/subscripciones/borrar/**")
				.hasAnyRole("INTERVENTOR")

				// Retos
				.pathMatchers(HttpMethod.GET, "/api/retos/retos/listar", "/api/retos/retos/listarNombre/**",
						"/api/suscripcionesretos/suscripciones/revisarLike/**",
						"/api/suscripcionesretos/suscripciones/revisarSuscripciones/**",
						"/api/suscripcionesretos/suscripciones/verNombre/**",
						"/api/estadisticaretos/estadistica/verIdeas/**")
				.hasAnyRole("ADMIN", "USER", "INTERVENTOR")
				.pathMatchers(HttpMethod.PUT, "/api/suscripcionesretos/suscripciones/ponerComentarios/**",
						"/api/suscripcionesretos/suscripciones/darLike/**",
						"/api/suscripcionesretos/suscripciones/listar",
						"/api/suscripcionesretos/suscripciones/suscribirse/**", "/api/retos/retos/ponerIdeas/**")
				.hasAnyRole("ADMIN", "USER").pathMatchers("/api/interventor/**").hasRole("INTERVENTOR")
				.pathMatchers("/api/parametrizacion/**", "/api/retos/**", "/api/suscripcionesretos/**",
						"/api/estadisticaretos/**")
				.hasRole("ADMIN")

				.anyExchange().authenticated()
				.and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
				.csrf().disable()
				.build();
	}

}
