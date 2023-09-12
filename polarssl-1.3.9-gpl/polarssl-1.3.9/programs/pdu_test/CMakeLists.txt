set(libs
     polarssl
)



set(targets
     appcli
     appser
)


add_executable(appcli appcli.c)
target_link_libraries(appcli ${libs})

add_executable(appser appser.c)
target_link_libraries(appser ${libs})


