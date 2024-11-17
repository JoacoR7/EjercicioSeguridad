
package com.is.biblioteca.business.persistence.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.is.biblioteca.business.domain.entity.Imagen;

public interface ImagenRepository extends JpaRepository<Imagen, String>{

}
