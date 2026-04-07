package com.huhao35.postauthserver;

import com.huhao35.postauthserver.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

    User findUserByFullName(String username);
    @Transactional
    @Modifying
    @Query(value = "UPDATE user SET available = false WHERE id = :id", nativeQuery = true)
    void deleteById(Long id);
}
