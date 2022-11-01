package com.security.springjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.security.springjwt.models.ERole;
import com.security.springjwt.models.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  default Optional<Role> findByName(ERole name){
    return findAll().stream().filter((role -> role.getName().equals(name))).findFirst();
  }
}
