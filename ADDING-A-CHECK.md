# Adding a check when a new article is approved

Notes for me. Do these in order.

1. Pick the folder name: `YYYY-MM-short-name`, using the month of the
   incident. Note the article slug from the site, the part after `/posts/`.

2. Copy the template.

   ```sh
   cd /workspace/breach-checks
   cp -r templates/check YYYY-MM-short-name
   ```

3. Collect the facts from primary sources only: the vendor advisory, the
   GHSA, the project's own incident post. Write down every indicator (hashes,
   file names, paths, versions, digests, domains) with the URL it came from.
   If a fact only comes from a researcher or a news site, say so in the
   README.

4. Write `check.sh`.
   - Read only. Never run the suspect thing. Never start the interpreter that
     loads the payload.
   - No network calls.
   - Put the source URL in a comment above each indicator list.
   - Keep the exit codes: 0 clean, 1 flagged, 2 usage error.
   - Add `BC_*` environment variables only when a test cannot set something
     up for real (a file's change time, a real malware hash). Document them in
     the header comment.

5. Write fixtures and `test.sh`.
   - Fixture files end in `.fixture`. `test.sh` copies them into a temp
     folder with the real names.
   - Test at least: a flagged case, a clean case, a near miss that must not be
     flagged, and a bad option (exit 2).
   - Say in `fixtures/README.md` why each fixture is harmless.

6. Run the checks.

   ```sh
   make lint
   make test
   for t in */test.sh; do PATH=/tmp/bb:$PATH busybox sh "$t" | tail -1; done   # BusyBox tools, if set up
   ```

7. Run the check on a real machine and paste the real output into the
   README. Never type example output by hand.

8. Write the README from the template. Plain words. No em or en dashes.
   Link the article: `https://sudodrift.github.io/posts/<slug>/`.

9. Add a row to the table in the top-level `README.md`.

10. Commit with the project identity.

    ```sh
    git add YYYY-MM-short-name README.md
    git -c user.name=sudodrift -c user.email=noreply@sudodrift.invalid \
      commit -m "Add YYYY-MM-short-name check"
    ```

11. Before pushing, check the author on the new commit:

    ```sh
    git log -1 --format='%an <%ae> | %cn <%ce>'
    ```

12. Push only after the article is live and the check has been reviewed.
