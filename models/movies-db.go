package models

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

type DBModel struct {
	DB *sql.DB
}

// Get returns one movie
// nts - *movie because it's a struct?
func (m *DBModel) Get(id int) (*Movie, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `select id, title, description, year, release_date, rating, runtime, mpaa_rating, 
			created_at, updated_at, coalesce(poster, '') from movies where id = $1
	`

	row := m.DB.QueryRowContext(ctx, query, id)

	var movie Movie

	err := row.Scan(
		&movie.ID,
		&movie.Title,
		&movie.Description,
		&movie.Year,
		&movie.ReleaseDate,
		&movie.Rating,
		&movie.Runtime,
		&movie.MPAARating,
		&movie.CreatedAt,
		&movie.UpdatedAt,
		&movie.Poster,
	)
	if err != nil {
		return nil, err
	}

	query = `
			select 
				mg.id, mg.movie_id, mg.genre_id, g.genre_name, mg.created_at, mg.updated_at 
			from 
				movies_genres mg
				left join genres g on (mg.genre_id = g.id)
			 where 
			 	mg.movie_id = $1
			`

	rows, _ := m.DB.QueryContext(ctx, query, id)
	defer rows.Close()
	genres := make(map[int]string)

	// nts - remember this syntax
	for rows.Next() {
		var genre MovieGenre
		err = rows.Scan(
			&genre.ID,
			&genre.MovieID,
			&genre.GenreID,
			&genre.Genre.GenreName,
			&genre.CreatedAt,
			&genre.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		genres[genre.ID] = genre.Genre.GenreName
	}
	movie.MovieGenre = genres

	return &movie, nil
}

// All returns all movies, taking zero or n params. A variadic function.
func (m *DBModel) All(genre ...int) ([]*Movie, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	where := ""
	if len(genre) > 0 {
		where = fmt.Sprintf("where id in (select movie_id from movies_genres where genre_id = %d)", genre[0])
	}

	query := fmt.Sprintf(`select id, title, description, year, release_date, rating, runtime, mpaa_rating, 
			created_at, updated_at, coalesce(poster, '') from movies %s order by title`, where)

	rows, err := m.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var movies []*Movie
	for rows.Next() {
		var movie Movie
		err := rows.Scan(
			&movie.ID,
			&movie.Title,
			&movie.Description,
			&movie.Year,
			&movie.ReleaseDate,
			&movie.Rating,
			&movie.Runtime,
			&movie.MPAARating,
			&movie.CreatedAt,
			&movie.UpdatedAt,
			&movie.Poster,
		)
		if err != nil {
			return nil, err
		}

		genreQuery := `
			select 
				mg.id, mg.movie_id, mg.genre_id, g.genre_name, mg.created_at, mg.updated_at 
			from 
				movies_genres mg
				left join genres g on (mg.genre_id = g.id)
			where 
				mg.movie_id = $1
			`

		genreRows, _ := m.DB.QueryContext(ctx, genreQuery, movie.ID)
		genres := make(map[int]string)

		for genreRows.Next() {
			var genre MovieGenre
			err = genreRows.Scan(
				&genre.ID,
				&genre.MovieID,
				&genre.GenreID,
				&genre.Genre.GenreName,
				&genre.CreatedAt,
				&genre.UpdatedAt,
			)
			if err != nil {
				return nil, err
			}
			genres[genre.ID] = genre.Genre.GenreName
		}
		genreRows.Close()

		movie.MovieGenre = genres

		movies = append(movies, &movie)
	}
	return movies, nil
}

func (m *DBModel) GenresAll() ([]*Genre, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := `select id, genre_name, created_at, updated_at from genres order by genre_name
	`
	rows, err := m.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var genres []*Genre
	for rows.Next() {
		var genre Genre
		err := rows.Scan(
			&genre.ID,
			&genre.GenreName,
			&genre.CreatedAt,
			&genre.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		genres = append(genres, &genre)

	}
	if err != nil {
		return nil, err
	}
	return genres, nil
}

func (m *DBModel) InsertMovie(movie Movie) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stmt := `insert into movies (title, description, year, release_date, runtime, rating, mpaa_rating,
			created_at, updated_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := m.DB.ExecContext(ctx, stmt,
		movie.Title,
		movie.Description,
		movie.Year,
		movie.ReleaseDate,
		movie.Runtime,
		movie.Rating,
		movie.MPAARating,
		movie.CreatedAt,
		movie.UpdatedAt,
		movie.Poster,
	)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil

}
func (m *DBModel) UpdateMovie(movie Movie) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stmt := `update movies set title = $1, description = $2, year = $3, release_date = $4, 
			runtime = $5, rating = $6, mpaa_rating = $7,
			updated_at = $8, poster = $9 where id = $10`

	_, err := m.DB.ExecContext(ctx, stmt,
		movie.Title,
		movie.Description,
		movie.Year,
		movie.ReleaseDate,
		movie.Runtime,
		movie.Rating,
		movie.MPAARating,
		movie.UpdatedAt,
		movie.Poster,
		movie.ID,
	)
	if err != nil {
		log.Println(err)

		return err
	}
	return nil

}

func (m *DBModel) DeleteMovie(id int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stmt := `delete from movies where id = $1`

	_, err := m.DB.ExecContext(ctx, stmt, id)
	if err != nil {
		return err
	}
	return nil
}
