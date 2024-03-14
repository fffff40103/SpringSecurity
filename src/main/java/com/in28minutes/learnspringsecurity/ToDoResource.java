package com.in28minutes.learnspringsecurity;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;



@RestController
public class ToDoResource {
	private Logger logger=LoggerFactory.getLogger(getClass());
	
	private static  List<Todo> lists=new ArrayList<>();
	
	private static final List<Todo> TODOS_LIST = 
			List.of(new Todo("in28minutes", "Learn AWS"),
					new Todo("in28minutes", "Get AWS Certified"));
	
	@GetMapping("/todos")
	public List<Todo> retrieveAllTodos() {
		return TODOS_LIST;
	}
	
	@GetMapping("/admin")
	public String testAdmin() {
		return "admin ok";
	}
	
	
	@GetMapping("/users/{username}/todos")
	@PreAuthorize("hasRole('USER') and #username == authentication.name")
	@PostAuthorize("returnObject.username=='scott'")
	@RolesAllowed({"ADMIN","USER"})
	@Secured({"ROLE_ADMIN","ROLE_USER"})
	public Todo retrieveSpecificUser(@PathVariable("username") String username){
		return TODOS_LIST.get(0);
	}
	
	@PostMapping("/users/{username}/todos")
	public void createSpecificUser(@PathVariable("username") String username,@RequestBody Todo todo) {
		System.out.println(todo.username());
		System.out.println(todo.description());
		logger.info("Create {} for {}", todo, username);
	}
	
}


record Todo (String username, String description) {}
