package org.synyx.urlaubsverwaltung.sicknote;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import org.synyx.urlaubsverwaltung.person.Person;

import java.util.Date;
import java.util.List;


/**
 * Repository for {@link SickNote} entities.
 *
 * @author  Aljona Murygina - murygina@synyx.de
 */
public interface SickNoteDAO extends JpaRepository<SickNote, Integer> {

    @Query(
        "SELECT x FROM SickNote x WHERE x.person = ?1 AND ((x.startDate BETWEEN ?2 AND ?3) OR (x.endDate BETWEEN ?2 AND ?3))"
    )
    List<SickNote> findByPersonAndPeriod(Person person, Date startDate, Date endDate);


    @Query("SELECT x FROM SickNote x WHERE ((x.startDate BETWEEN ?1 AND ?2) OR (x.endDate BETWEEN ?1 AND ?2))")
    List<SickNote> findByPeriod(Date startDate, Date endDate);
}